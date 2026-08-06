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
