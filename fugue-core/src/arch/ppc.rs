#[cfg(feature = "static-lifters")]
pub use fugue_lifter::ppc::*;

use fugue_bytes::Endian;

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
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
            "r26", "r27", "r28", "r29", "r30", "r31", "pc",
        ]
        .map(|name| {
            register(name)
                .unwrap_or_else(|| panic!("PowerPC language must define register `{name}`"))
        });
        Self { gprs }
    }
}

#[derive(Clone)]
pub struct Ppc {
    data: ArchData,
    language: &'static Language,
}

impl ArchT for Ppc {
    fn lifter(&self) -> Lifter {
        Lifter::from(Arch::from(Box::new(self.clone()) as Box<dyn ArchT>))
    }

    fn external_thunk_template(&self) -> ExternalThunkTemplate {
        let mut bytes = [0x20, 0x00, 0x80, 0x4e];
        if self.language().endian().is_big() {
            bytes.reverse();
        }
        ExternalThunkTemplate::new(bytes)
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl Ppc {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let data = ArchData::new(language);
        Arch::from(Box::new(Self { data, language }) as Box<dyn ArchT>)
    }

    pub fn resolve_default_variant(endian: Endian) -> Result<&'static Language, LanguageError> {
        Self::resolve_variant(endian, None)
    }

    pub fn resolve_variant<'a>(
        endian: Endian,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => {
                return Ok(match endian {
                    Endian::Big => be::variants::DEFAULT,
                    Endian::Little => le::variants::DEFAULT,
                });
            }
            _ => {}
        }
        let loader = LanguageLoader::from_env()?;
        Self::resolve_variant_with(&loader, endian, variant)
    }

    pub fn resolve_variant_with<'a>(
        loader: &LanguageLoader,
        endian: Endian,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => {
                return Ok(match endian {
                    Endian::Big => be::variants::DEFAULT,
                    Endian::Little => le::variants::DEFAULT,
                });
            }
            _ => {}
        }
        let lid = LanguageId::new_with("PowerPC", endian, 32, variant);
        loader.load(&lid)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "ppc";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "PowerPC" && language.bits() == 32
    }

    fn create(language: &'static Language) -> Arch {
        Ppc::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "ppc";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "PowerPC" || id.bits() != 32 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => Ppc::resolve_variant_with(loader, id.endian(), id.variant())?,
            None => Ppc::resolve_variant(id.endian(), id.variant())?,
        };

        Ok(Some(language))
    }
}
