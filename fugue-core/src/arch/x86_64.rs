use yaxpeax_arch::*;
use yaxpeax_x86::amd64::{DecodeError, InstDecoder, Instruction, Opcode};

use fugue_lifter::x86_64::register::{
    AF, CF, DF, OF, PF, R8, R9, R10, R11, R12, R13, R14, R15, RAX, RBP, RBX, RCX, RDI, RDX, RSI,
    RSP, SF, ZF,
};
use fugue_lifter::x86_64::user_op::{INVALID_INSTRUCTION_EXCEPTION, SWI};
pub use fugue_lifter::x86_64::*;

use crate::arch::{Arch, ArchImpl, Flag};
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties};
use crate::lifter::{
    Disassembler, DisassemblerError, DisassemblerImpl, LanguageVariant, Lifter, LiftingContext,
};

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
        X86_64Disassembler::new()
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
        Arch::from(Box::new(Self { language }) as Box<dyn ArchImpl>)
    }
}

struct X86_64Disassembler {
    decoder: InstDecoder,
}

impl X86_64Disassembler {
    fn new() -> Disassembler {
        Disassembler::new(Self {
            decoder: InstDecoder::default(),
        })
    }

    fn should_lift(&self, insn: &Instruction) -> bool {
        matches!(
            insn.opcode(),
            Opcode::JO
                | Opcode::JB
                | Opcode::JZ
                | Opcode::JA
                | Opcode::JS
                | Opcode::JP
                | Opcode::JL
                | Opcode::JG
                | Opcode::JMP
                | Opcode::JNO
                | Opcode::JNB
                | Opcode::JNZ
                | Opcode::JNA
                | Opcode::JNS
                | Opcode::JNP
                | Opcode::JGE
                | Opcode::JLE
                | Opcode::JMPF
                | Opcode::JMPE
                | Opcode::JRCXZ
                | Opcode::CALL
                | Opcode::CALLF
                | Opcode::RETF
                | Opcode::RETURN
                | Opcode::HLT
                | Opcode::INT
                | Opcode::UD2
        )
    }
}

impl DisassemblerImpl for X86_64Disassembler {
    fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: &[u8],
        _context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let mut reader = yaxpeax_arch::U8Reader::new(bytes);
        let insn = match self.decoder.decode(&mut reader) {
            Ok(insn) => {
                let size = insn.len().to_const() as usize;
                Insn::from_disassembly(
                    address,
                    size,
                    if self.should_lift(&insn) {
                        InsnProperties::NEEDS_LIFTING
                    } else {
                        InsnProperties::FALL
                    },
                )
            }
            Err(DecodeError::IncompleteDecoder) => {
                Insn::from_disassembly(address, 0, InsnProperties::NEEDS_LIFTING)
            }
            Err(e) => {
                return Err(DisassemblerError::disassembler(e));
            }
        };
        Ok(insn)
    }
}
