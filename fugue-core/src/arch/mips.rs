#[cfg(feature = "static-lifters")]
pub use fugue_lifter::mips::*;

use crate::arch::Arch;
use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::ir::ExternFunctionTemplate;
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::{Language, LanguageError, LanguageId, LanguageLoader, Lifter, Varnode};

#[derive(Clone)]
struct ArchData {
    gprs: Vec<Varnode>,
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
        let reg = |name| language.register_by_name(name);

        let gprs = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
            "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "s8", "ra", "pc",
        ]
        .into_iter()
        .filter_map(reg)
        .collect();

        Self { gprs }
    }
}

#[derive(Clone)]
pub struct Mips {
    language: &'static Language,
    data: ArchData,
}

impl ArchT for Mips {
    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        let mut bytes = [0x08, 0x00, 0xe0, 0x03]; // jr $ra
        if self.language().is_big_endian() {
            bytes.reverse();
        }
        ExternFunctionTemplate::new(bytes)
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl Mips {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let data = ArchData::new(language);
        Arch::from(Box::new(Self { language, data }) as Box<dyn ArchT>)
    }

    pub fn resolve_default_variant(is_be: bool) -> Result<&'static Language, LanguageError> {
        Self::resolve_variant(is_be, None)
    }

    pub fn resolve_variant<'a>(
        is_be: bool,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => {
                return Ok(if is_be {
                    be::variants::DEFAULT
                } else {
                    le::variants::DEFAULT
                });
            }
            _ => {}
        }
        let loader = LanguageLoader::from_env()?;
        Self::resolve_variant_with(&loader, is_be, variant)
    }

    pub fn resolve_variant_with<'a>(
        loader: &LanguageLoader,
        is_be: bool,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => {
                return Ok(if is_be {
                    be::variants::DEFAULT
                } else {
                    le::variants::DEFAULT
                });
            }
            _ => {}
        }
        let lid = LanguageId::new_with("MIPS", is_be, 32, variant);
        loader.load(&lid)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "mips";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "MIPS" && language.address_bits() == 32
    }

    fn create(language: &'static Language) -> Arch {
        Mips::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "mips";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "MIPS" || id.bits() != 32 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => Mips::resolve_variant_with(loader, id.is_big_endian(), id.variant())?,
            None => Mips::resolve_variant(id.is_big_endian(), id.variant())?,
        };

        Ok(Some(language))
    }
}
