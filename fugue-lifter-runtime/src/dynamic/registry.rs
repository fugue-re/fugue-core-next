use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::language::{Language, LanguageId};

static REGISTRY: OnceLock<RwLock<HashMap<LanguageId, &'static Language>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<LanguageId, &'static Language>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) fn intern_or_install<F>(id: LanguageId, install: F) -> &'static Language
where
    F: FnOnce() -> &'static Language,
{
    if let Some(existing) = registry()
        .read()
        .expect("registry rwlock poisoned")
        .get(&id)
    {
        return existing;
    }
    let language = install();
    registry()
        .write()
        .expect("registry rwlock poisoned")
        .entry(id)
        .or_insert(language);
    language
}

pub(crate) fn lookup(id: &LanguageId) -> Option<&'static Language> {
    registry()
        .read()
        .expect("registry rwlock poisoned")
        .get(id)
        .copied()
}
