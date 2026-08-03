#[cfg(feature = "static-lifters")]
pub use fugue_lifter::ppc64::*;

use crate::arch::Arch;
use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::ExternFunctionTemplate;
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::{Disassembler, Language, LanguageError, LanguageId, LanguageLoader, Lifter};

#[derive(Clone)]
struct ArchData {
    gprs: [Varnode; 33],
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
        let reg = |name| language.register_by_name(name);

        let gprs = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
            "r26", "r27", "r28", "r29", "r30", "r31", "pc",
        ]
        .map(|name| {
            reg(name).unwrap_or_else(|| panic!("PowerPC language must define register `{name}`"))
        });

        Self { gprs }
    }
}

#[derive(Clone)]
pub struct Ppc64 {
    language: &'static Language,
    data: ArchData,
}

impl ArchT for Ppc64 {
    fn disassembler(&self) -> Disassembler {
        Disassembler::new(self.lifter())
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        let mut bytes = [0x20, 0x00, 0x80, 0x4e];
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

impl Ppc64 {
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
            Some("64-32addr") => {
                return Ok(if is_be {
                    be::variants::V64_32ADDR
                } else {
                    le::variants::V64_32ADDR
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
            Some("64-32addr") => {
                return Ok(if is_be {
                    be::variants::V64_32ADDR
                } else {
                    le::variants::V64_32ADDR
                });
            }
            _ => {}
        }
        let lid = LanguageId::new_with("PowerPC", is_be, 64, variant);
        Ok(loader.load(&lid)?)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "ppc64";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "PowerPC" && language.bits() == 64
    }

    fn create(language: &'static Language) -> Arch {
        Ppc64::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "ppc64";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "PowerPC" || id.bits() != 64 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => Ppc64::resolve_variant_with(loader, id.is_big_endian(), id.variant())?,
            None => Ppc64::resolve_variant(id.is_big_endian(), id.variant())?,
        };

        Ok(Some(language))
    }
}
