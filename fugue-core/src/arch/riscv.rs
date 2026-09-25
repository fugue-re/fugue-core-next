#[cfg(feature = "static-lifters")]
pub use fugue_lifter::riscv::*;

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, ExternalThunkTemplate};
use crate::lifter::{
    Language, LanguageError, LanguageId, LanguageLoader, LanguageSource, Lifter, Varnode,
};

#[derive(Clone)]
struct ArchData {
    gprs: [Varnode; 33],
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
        let register = |name| language.register_by_name(name);
        let gprs = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
            "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6", "pc",
        ]
        .map(|name| {
            register(name).unwrap_or_else(|| panic!("RISCV language must define register `{name}`"))
        });
        Self { gprs }
    }
}

#[derive(Clone)]
pub struct RiscV {
    data: ArchData,
    language: &'static Language,
}

impl ArchT for RiscV {
    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_thunk_template(&self) -> ExternalThunkTemplate {
        ExternalThunkTemplate::new([0x67, 0x80, 0x00, 0x00])
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl RiscV {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let data = ArchData::new(language);
        Arch::from(Box::new(Self { data, language }) as Box<dyn ArchT>)
    }

    pub fn resolve_default_variant() -> Result<&'static Language, LanguageError> {
        Self::resolve_variant(None)
    }

    pub fn resolve_variant<'a>(
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => return Ok(variants::DEFAULT),
            _ => {}
        }
        let loader = LanguageLoader::from_env()?;
        Self::resolve_variant_with(&loader, variant)
    }

    pub fn resolve_variant_with<'a>(
        loader: &LanguageLoader,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => return Ok(variants::DEFAULT),
            _ => {}
        }
        let lid = LanguageId::new_with("RISCV", false, 32, variant);
        loader.load(&lid)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "riscv";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "RISCV" && language.bits() == 32
    }

    fn create(language: &'static Language) -> Arch {
        RiscV::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "riscv";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "RISCV" || id.bits() != 32 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => RiscV::resolve_variant_with(loader, id.variant())?,
            None => RiscV::resolve_variant(id.variant())?,
        };

        Ok(Some(language))
    }
}
