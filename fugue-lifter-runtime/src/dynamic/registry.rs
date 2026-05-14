use std::collections::HashMap;
use std::sync::Mutex;

use crate::language::{Language, LanguageId};

static REGISTRY: Mutex<Option<HashMap<LanguageId, &'static Language>>> = Mutex::new(None);

pub(crate) fn intern_or_install<F>(id: LanguageId, install: F) -> &'static Language
where
    F: FnOnce() -> &'static Language,
{
    let mut guard = REGISTRY.lock().expect("registry mutex poisoned");
    let map = guard.get_or_insert_with(HashMap::new);
    map.entry(id).or_insert_with(install)
}

pub fn lookup(id: &LanguageId) -> Option<&'static Language> {
    let guard = REGISTRY.lock().expect("registry mutex poisoned");
    guard.as_ref().and_then(|m| m.get(id).copied())
}
