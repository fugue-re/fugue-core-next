#[cfg(not(feature = "dynamic"))]
pub use fugue_lifter::mips::*;

use crate::arch::Arch;
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::ExternFunctionTemplate;
use crate::lifter::{Disassembler, Language, LanguageVariant, Lifter};

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
    language: LanguageVariant,
    data: ArchData,
}

impl ArchT for Mips {
    fn disassembler(&self) -> Disassembler {
        Disassembler::new(self.lifter())
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language())
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

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl Mips {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        let data = ArchData::new(language.language());
        Arch::from(Box::new(Self { language, data }) as Box<dyn ArchT>)
    }
}

#[cfg(not(feature = "dynamic"))]
pub fn parse_language(is_le: bool, variant: Option<&str>) -> Option<LanguageVariant> {
    match variant {
        None | Some("default") => {
            Some(if is_le { le::variants::DEFAULT } else { be::variants::DEFAULT })
        }
        _ => None,
    }
}
