use crate::arch::{Arch, ArchImpl};
use crate::lifter::aarch64::le::register::{
    X0, X1, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X2, X20, X21, X22, X23, X24, X25,
    X26, X27, X28, X29, X3, X30, X4, X5, X6, X7, X8, X9,
};
use crate::lifter::{Disassembler, Language, LanguageVariant, Lifter, LifterBuilder, Varnode};
use crate::loader::symbols::ExternFunctionTemplate;

const GPRS: &[Varnode] = &[
    X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20,
    X21, X22, X23, X24, X25, X26, X27, X28, X29, X30,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AArch64 {
    language: &'static Language,
    variant: Option<LanguageVariant>,
}

impl ArchImpl for AArch64 {
    fn dissassembler(&self) -> Disassembler {
        todo!()
    }

    fn lifter(&self) -> Lifter {
        LifterBuilder::build_str(self.language.id()).expect("supported language")
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        ExternFunctionTemplate::new([0xc0, 0x03, 0x5f, 0xd6]) // RET
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        bytes == &[0x00u8, 0x00u8, 0x00u8, 0x00u8]
    }

    fn gprs(&self) -> &[Varnode] {
        GPRS
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl AArch64 {
    pub(crate) fn new(language: &'static Language) -> Arch {
        Self::new_with(language, None)
    }

    pub(crate) fn new_with(
        language: &'static Language,
        variant: impl Into<Option<LanguageVariant>>,
    ) -> Arch {
        Arch::from(Box::new(Self {
            language,
            variant: variant.into(),
        }) as Box<dyn ArchImpl>)
    }
}
