use fugue_lifter::mips::register::{
    A0, A1, A2, A3, AT, GP, K0, K1, PC, RA, S0, S1, S2, S3, S4, S5, S6, S7, S8, SP, T0, T1, T2, T3,
    T4, T5, T6, T7, T8, T9, V0, V1, ZERO,
};
pub use fugue_lifter::mips::*;

use crate::arch::Arch;
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::ExternFunctionTemplate;
use crate::lifter::{Disassembler, LanguageVariant, Lifter};

const GPRS: &[Varnode] = &[
    ZERO, AT, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3, T4, T5, T6, T7, S0, S1, S2, S3, S4, S5, S6,
    S7, T8, T9, K0, K1, GP, SP, S8, RA, PC,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mips {
    language: LanguageVariant,
}

impl ArchT for Mips {
    fn dissassembler(&self) -> Disassembler {
        let lifter = Lifter::new(self.language.language(), self.language.context()());
        Disassembler::new(lifter)
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language(), self.language.context()())
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        let mut bytes = [0x08, 0x00, 0xe0, 0x03]; // jr $ra
        if self.language().is_big_endian() {
            bytes.reverse();
        }
        ExternFunctionTemplate::new(bytes)
    }

    fn gprs(&self) -> &[Varnode] {
        GPRS
    }

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl Mips {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        Arch::from(Box::new(Self { language }) as Box<dyn ArchT>)
    }
}
