use crate::arch::{Arch, ArchImpl, Flag};
use crate::lifter::x86_64::register::{
    AF, CF, DF, OF, PF, R10, R11, R12, R13, R14, R15, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, RSI,
    RSP, SF, ZF,
};
use crate::lifter::x86_64::user_op::{INVALID_INSTRUCTION_EXCEPTION, SWI};
use crate::lifter::{Disassembler, LanguageVariant, Lifter, Varnode};
use crate::loader::symbols::ExternFunctionTemplate;

const FLAGS: &[Flag] = &[
    Flag::a(AF),
    Flag::c(CF),
    Flag::new(DF),
    Flag::v(OF),
    Flag::p(PF),
    Flag::n(SF),
    Flag::z(ZF),
];
const GPRS: &[Varnode] = &[
    RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X86_64 {
    language: LanguageVariant,
}

impl ArchImpl for X86_64 {
    fn dissassembler(&self) -> Disassembler {
        todo!()
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language(), self.language.context()())
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        ExternFunctionTemplate::new([0xc3])
    }

    fn flags(&self) -> &[Flag] {
        FLAGS
    }

    fn frame_pointer(&self) -> Option<Varnode> {
        Some(RBP)
    }

    fn gprs(&self) -> &[Varnode] {
        GPRS
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        const NONSENSE: &[&[u8]] = &[&[0x00u8, 0x00u8], &[0x00u8], &[0xf0u8]];
        NONSENSE.contains(&bytes)
    }

    fn is_skip_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        op == SWI && args.first().copied() == Some(Varnode::constant(0x3, 8)) // int3
            || op == INVALID_INSTRUCTION_EXCEPTION // ud2
    }

    fn is_trap_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        op == SWI && args.first().copied() == Some(Varnode::constant(0x3, 8)) // int3
            || op == INVALID_INSTRUCTION_EXCEPTION // ud2
    }

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl X86_64 {
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        Arch::from(Box::new(Self {
            language,
        }) as Box<dyn ArchImpl>)
    }
}
