use std::env;
use std::path::{Path, PathBuf};

use fugue_bytes::Endian;
use fugue_lifter::runtime::Language;
use fugue_sleigh_language::LanguageDB;

use crate::arch::registry as arch_registry;
use crate::lifter::{LanguageError, LanguageId};

const ENV_VAR: &str = "FUGUE_LANGUAGE_DIR";

pub struct LanguageLoader {
    db: LanguageDB,
}

impl From<LanguageDB> for LanguageLoader {
    fn from(db: LanguageDB) -> Self {
        Self { db }
    }
}

impl LanguageLoader {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, LanguageError> {
        Ok(Self {
            db: LanguageDB::from_directory_with(root, true)?,
        })
    }

    pub fn from_env() -> Result<Self, LanguageError> {
        let root = env::var_os(ENV_VAR).ok_or(LanguageError::Environment(ENV_VAR))?;
        Self::new(PathBuf::from(root))
    }

    pub fn database(&self) -> &LanguageDB {
        &self.db
    }

    pub fn load(&self, lid: &LanguageId) -> Result<&'static Language, LanguageError> {
        if let Some(existing) = Language::lookup(lid) {
            return Ok(existing);
        }

        let endian = if lid.is_big_endian() {
            Endian::Big
        } else {
            Endian::Little
        };
        let processor = lid.processor();
        let bits = lid.bits();
        let builder = match lid.variant() {
            Some(variant) => self.db.lookup(processor, endian, bits, variant),
            None => self.db.lookup_default(processor, endian, bits),
        }
        .ok_or(LanguageError::Unsupported)?;

        let sla = builder.language().sla_file();
        let parent = sla.parent().unwrap_or_else(|| Path::new("."));

        let endian_tag = if lid.is_big_endian() { "BE" } else { "LE" };
        let variant = lid.variant().unwrap_or("default");
        let candidate = parent.join(format!("{processor}-{endian_tag}-{bits}-{variant}.flift"));
        if candidate.is_file() {
            return Ok(Language::from_file(&candidate)?);
        }

        Ok(Language::from_sleigh_with_sla(
            parent,
            lid.to_string(),
            sla,
        )?)
    }

    pub fn load_from(&self, path: impl AsRef<Path>) -> Result<&'static Language, LanguageError> {
        let path = path.as_ref();
        match path.extension().and_then(|e| e.to_str()) {
            Some("flift") => Ok(Language::from_file(path)?),
            Some("sla") => {
                let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                let matches = self
                    .db
                    .iter()
                    .filter(|b| {
                        b.language()
                            .sla_file()
                            .canonicalize()
                            .is_ok_and(|p| p == canonical)
                    })
                    .collect::<Vec<_>>();

                if matches.is_empty() {
                    return Err(LanguageError::Unsupported);
                }

                let builder = matches
                    .iter()
                    .find(|b| b.language().architecture().variant() == "default")
                    .or_else(|| (matches.len() == 1).then(|| &matches[0]))
                    .ok_or_else(|| LanguageError::ambiguous_sla(canonical))?;

                let arch = builder.language().architecture();
                let variant = (arch.variant() != "default").then(|| arch.variant());
                let lid = LanguageId::new_with(
                    arch.processor(),
                    arch.endian().is_big(),
                    arch.bits(),
                    variant,
                );
                self.load(&lid)
            }
            _ => Err(LanguageError::unsupported_extension(path)),
        }
    }
}

pub struct LanguageSource<'a> {
    loader: Option<&'a LanguageLoader>,
}

impl Default for LanguageSource<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> LanguageSource<'a> {
    pub const fn new() -> Self {
        Self { loader: None }
    }

    pub const fn new_with(loader: &'a LanguageLoader) -> Self {
        Self {
            loader: Some(loader),
        }
    }

    pub fn loader(&self) -> Option<&LanguageLoader> {
        self.loader
    }

    pub fn load(&self, id: &LanguageId) -> Result<&'static Language, LanguageError> {
        resolve_language_with_source(id, self)
    }
}

pub(crate) fn resolve_language_with_source(
    id: &LanguageId,
    source: &LanguageSource<'_>,
) -> Result<&'static Language, LanguageError> {
    match arch_registry::provide_language(id, source)? {
        Some(language) => Ok(language),
        None => match source.loader() {
            Some(loader) => Ok(loader.load(id)?),
            None => {
                let loader = LanguageLoader::from_env()?;
                Ok(loader.load(id)?)
            }
        },
    }
}

pub fn resolve_language_id(id: &LanguageId) -> Result<&'static Language, LanguageError> {
    resolve_language_with_source(id, &LanguageSource::new())
}

pub fn resolve_language_id_with(
    id: &LanguageId,
    loader: &LanguageLoader,
) -> Result<&'static Language, LanguageError> {
    resolve_language_with_source(id, &LanguageSource::new_with(loader))
}

pub fn resolve_language(s: impl AsRef<str>) -> Result<&'static Language, LanguageError> {
    let id = s.as_ref().parse::<LanguageId>()?;
    resolve_language_id(&id)
}

pub fn resolve_language_with(
    s: impl AsRef<str>,
    loader: &LanguageLoader,
) -> Result<&'static Language, LanguageError> {
    let id = s.as_ref().parse::<LanguageId>()?;
    resolve_language_id_with(&id, loader)
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use fugue_bytes::Endian;

    use super::LanguageLoader;
    use crate::lifter::LanguageId;

    #[test]
    fn loader_resolves_variants_whose_ldefs_attributes_differ()
    -> Result<(), Box<dyn std::error::Error>> {
        let specs = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("fugue-lifter-ppc/data/processors");
        let loader = LanguageLoader::new(specs)?;
        let db = loader.database();

        for variant in ["default", "64-32addr", "A2ALT", "A2ALT-32addr"] {
            let id = LanguageId::new_with("PowerPC", true, 64, Some(variant));
            assert!(
                db.lookup("PowerPC", Endian::Big, 64, variant).is_some(),
                "{id} must resolve against the language database",
            );
        }

        Ok(())
    }
}
