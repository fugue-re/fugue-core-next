use std::any::Any;
use std::mem::size_of;
use std::sync::Arc;

use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::{DefaultHashBuilder, OptionsBuilder, Weighter};

use crate::il::common::{IlArtefact, IlError, IlFormId};
use crate::il::ecode::ECodeIr;
use crate::il::mcode::MCodeIr;
use crate::il::pcode::PCodeIr;
use crate::ir::cfg::FlowTargets;
use crate::ir::{Address, FunctionId};

const CFG_CACHE_CAPACITY: usize = 1024;
const ESTIMATED_LIFTED_CACHE_ENTRIES: usize = 256;

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

pub trait QueryableIl: IlArtefact {}

impl QueryableIl for PCodeIr {}

impl QueryableIl for ECodeIr {}

impl QueryableIl for MCodeIr {}

impl QueryCache {
    pub(crate) fn new(lifted_cache_bytes: usize) -> Self {
        let lifted_options = OptionsBuilder::new()
            .shards(1)
            .estimated_items_capacity(ESTIMATED_LIFTED_CACHE_ENTRIES)
            .weight_capacity(lifted_cache_bytes as u64)
            .hot_allocation(1.0)
            .build()
            .expect("valid lifted cache configuration");

        Self {
            flow_targets: Cache::new(CFG_CACHE_CAPACITY),
            lifted: Cache::with_options(
                lifted_options,
                LiftedWeigher,
                DefaultHashBuilder::default(),
                DefaultLifecycle::default(),
            ),
            lifted_cache_bytes,
        }
    }

    pub(crate) fn flow_targets(&self, entry: Address) -> CacheLookup<FlowTargets> {
        CacheLookup::from_cached(self.flow_targets.get(&entry))
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
        self.clear_lifted();
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use quick_cache::Weighter;

    use super::{CacheLookup, CachedIl, LiftedWeigher, QueryCache};
    use crate::il::common::{IlArtefact, IlError, IlFormId};
    use crate::il::pcode::PCodeIr;
    use crate::ir::FunctionId;

    #[test]
    fn lifted_entries_use_the_complete_byte_budget() {
        let function = FunctionId::default();
        let form = IlFormId::from_static("acme.cache.boundary");
        let payload = 128usize;
        let key = (function, form.clone());
        let entry = Some(CachedIl {
            value: Arc::new(0u8),
            size: payload,
        });
        let budget = LiftedWeigher.weight(&key, &entry) as usize;

        for size in [payload - 1, payload] {
            let cache = QueryCache::new(budget);
            cache.insert_lifted_erased(function, &form, Some(Arc::new(0u8)), size);
            assert!(matches!(
                cache.lifted_erased(function, &form),
                CacheLookup::Hit(_)
            ));
        }

        let cache = QueryCache::new(budget);
        cache.insert_lifted_erased(function, &form, Some(Arc::new(0u8)), payload + 1);
        assert!(matches!(
            cache.lifted_erased(function, &form),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn a_cached_type_mismatch_is_not_a_cache_miss() {
        let cache = QueryCache::new(4096);
        let function = FunctionId::default();
        cache.insert_lifted_erased(function, &PCodeIr::FORM, Some(Arc::new(0u8)), 1);

        assert!(matches!(
            cache.lifted::<PCodeIr>(function),
            Err(IlError::MismatchedArtefact { form }) if form == PCodeIr::FORM
        ));
    }
}
