use thiserror::Error;

use crate::arch::Arch;
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::{Language, LanguageError, LanguageId};
use crate::registry::{self, Registration};

#[derive(Debug, Error)]
pub enum ArchError {
    #[error("ambiguous architecture provider for language `{0}`")]
    AmbiguousProvider(String),
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
}

type ArchSupportsFn = fn(&'static Language) -> bool;
type ArchCreateFn = fn(&'static Language) -> Arch;
type LanguageProvideFn = fn(
    id: &LanguageId,
    source: &LanguageSource<'_>,
) -> Result<Option<&'static Language>, LanguageError>;

pub struct ArchProvider {
    pub name: &'static str,
    pub supports: ArchSupportsFn,
    pub create: ArchCreateFn,
}

impl ArchProvider {
    pub fn supports(&self, language: &'static Language) -> bool {
        (self.supports)(language)
    }

    pub fn create(&self, language: &'static Language) -> Arch {
        (self.create)(language)
    }
}

impl Registration for ArchProvider {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(ArchProvider);

pub struct LanguageProvider {
    pub name: &'static str,
    pub provide: LanguageProvideFn,
}

impl LanguageProvider {
    pub fn provide(
        &self,
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        (self.provide)(id, source)
    }
}

impl Registration for LanguageProvider {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(LanguageProvider);

pub fn provide_arch(language: &'static Language) -> Result<Arch, ArchError> {
    let mut matches = registry::iter::<ArchProvider>()
        .filter(|provider| provider.supports(language))
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Err(ArchError::UnsupportedLanguage(language.to_string())),
        1 => Ok(matches.remove(0).create(language)),
        _ => Err(ArchError::AmbiguousProvider(language.to_string())),
    }
}

pub fn provide_language(
    id: &LanguageId,
    source: &LanguageSource<'_>,
) -> Result<Option<&'static Language>, LanguageError> {
    let mut resolved = Vec::new();

    for provider in registry::iter::<LanguageProvider>() {
        if let Some(language) = provider.provide(id, source)? {
            resolved.push(language);
        }
    }

    match resolved.len() {
        0 => Ok(None),
        1 => Ok(resolved.pop()),
        _ => Err(LanguageError::AmbiguousProvider(id.to_string())),
    }
}
