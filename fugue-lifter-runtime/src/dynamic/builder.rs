use std::path::Path;

use crate::context::ContextDatabase;
use crate::dynamic::LanguageLoadError;
use crate::language::Language;
use crate::lifter::Lifter;
use crate::pcode::LiftingContext;

pub struct LanguageBuilder {
    language: &'static Language,
}

impl LanguageBuilder {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, LanguageLoadError> {
        let language = Language::from_bytes(bytes.as_ref())?;
        Ok(Self { language })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LanguageLoadError> {
        let language = Language::from_file(path)?;
        Ok(Self { language })
    }

    pub fn from_sleigh(specs: impl AsRef<Path>, id: &str) -> Result<Self, LanguageLoadError> {
        let language = Language::from_sleigh(specs, id)?;
        Ok(Self { language })
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn apply_context(&self, db: &mut ContextDatabase) {
        for (name, value) in self.language.context_defaults() {
            if let Some(bits) = self.language.context_variable_by_name(name) {
                db.set_variable_default_by_bits(bits, *value);
            }
        }
    }

    pub fn context(&self) -> ContextDatabase {
        self.language.default_context()
    }

    pub fn lifter(&self, ninputs: usize) -> Lifter {
        let context = self.context();
        let lifting =
            LiftingContext::new(self.language, ninputs, context, self.language.unique_mask());
        Lifter::new(self.language, lifting)
    }
}
