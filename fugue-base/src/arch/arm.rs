use crate::arch::{Arch, ArchImpl};
use crate::lifter::arm::le::context::T_MODE;
use crate::lifter::arm::le::register::{
    LR, PC, R0, R1, R10, R11, R12, R2, R3, R4, R5, R6, R7, R8, R9, SP,
};
use crate::lifter::{ContextSet, Disassembler, Language, Lifter, LifterBuilder, Varnode};
use crate::loader::symbols::ExternFunctionTemplate;
use crate::types::Address;

const GPRS: &[Varnode] = &[
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP, LR, PC,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Arm {
    language: &'static Language,
}

impl ArchImpl for Arm {
    fn dissassembler(&self) -> Disassembler {
        todo!()
    }

    fn lifter(&self) -> Lifter {
        LifterBuilder::build_str(self.language.id()).expect("supported language")
    }

    fn canonicalise_address(&self, addr: Address) -> Option<(Address, ContextSet)> {
        let t_mode = (addr.offset() & 0x1) as u32;
        // TODO: check if ARM ldef will remove the LSB.
        let naddr = addr.wrap(self.language());
        (naddr == addr).then_some((naddr, ContextSet::single(T_MODE, t_mode)))
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        let mut bytes = [0x1e, 0xff, 0x2f, 0xe1];
        if self.language.is_big_endian() {
            bytes.reverse();
        }
        ExternFunctionTemplate::new_with(bytes, ContextSet::single(T_MODE, 0))
    }

    fn gprs(&self) -> &[Varnode] {
        GPRS
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl Arm {
    pub(crate) fn new(language: &'static Language) -> Arch {
        Arch::from(Box::new(Self { language }) as Box<dyn ArchImpl>)
    }
}
