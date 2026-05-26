use std::env;
use std::path::{Path, PathBuf};

use fugue_bytes::Endian;
use fugue_lifter::runtime::Language;
use fugue_sleigh_language::LanguageDB;

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
                let mut matches = self
                    .db
                    .iter()
                    .filter(|b| {
                        b.language()
                            .sla_file()
                            .canonicalize()
                            .map(|p| p == canonical)
                            .unwrap_or(false)
                    })
                    .collect::<Vec<_>>();

                if matches.is_empty() {
                    return Err(LanguageError::Unsupported);
                }

                let builder = if let Some(idx) = matches
                    .iter()
                    .position(|b| b.language().architecture().variant() == "default")
                {
                    matches.swap_remove(idx)
                } else if matches.len() == 1 {
                    matches.swap_remove(0)
                } else {
                    return Err(LanguageError::ambiguous_sla(canonical));
                };

                let arch = builder.language().architecture();
                let variant = (arch.variant() != "default").then(|| arch.variant().to_owned());
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
