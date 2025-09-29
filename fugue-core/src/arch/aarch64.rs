use yaxpeax_arch::*;
use yaxpeax_arm::armv8::a64::{DecodeError, InstDecoder, Instruction, Opcode};

use fugue_lifter::aarch64::register::{
    X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20,
    X21, X22, X23, X24, X25, X26, X27, X28, X29, X30,
};
pub use fugue_lifter::aarch64::*;

use crate::arch::{Arch, ArchImpl};
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties};
use crate::lifter::{
    Disassembler, DisassemblerError, DisassemblerImpl, LanguageVariant, Lifter, LiftingContext,
};

const GPRS: &[Varnode] = &[
    X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20,
    X21, X22, X23, X24, X25, X26, X27, X28, X29, X30,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AArch64 {
    language: LanguageVariant,
}

impl ArchImpl for AArch64 {
    fn dissassembler(&self) -> Disassembler {
        AArch64Disassembler::new()
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language(), self.language.context()())
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

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl AArch64 {
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        Arch::from(Box::new(Self { language }) as Box<dyn ArchImpl>)
    }
}

struct AArch64Disassembler {
    decoder: InstDecoder,
}

impl AArch64Disassembler {
    fn new() -> Disassembler {
        Disassembler::new(Self {
            decoder: InstDecoder::default(),
        })
    }

    fn should_lift(&self, insn: &Instruction) -> bool {
        matches!(
            insn.opcode,
            Opcode::B
                | Opcode::BL
                | Opcode::BLR
                | Opcode::BLRAA
                | Opcode::BLRAAZ
                | Opcode::BLRAB
                | Opcode::BLRABZ
                | Opcode::BR
                | Opcode::BRAA
                | Opcode::BRAAZ
                | Opcode::BRAB
                | Opcode::BRABZ
                | Opcode::BRK
                | Opcode::CBZ
                | Opcode::CBNZ
                | Opcode::ERET
                | Opcode::ERETAA
                | Opcode::ERETAB
                | Opcode::HINT
                | Opcode::HLT
                | Opcode::HVC
                | Opcode::RET
                | Opcode::RETAA
                | Opcode::RETAB
                | Opcode::SMC
                | Opcode::SVC
                | Opcode::TBL
                | Opcode::TBNZ
                | Opcode::TBZ
                | Opcode::TBX
                | Opcode::UDF
        )
    }
}

impl DisassemblerImpl for AArch64Disassembler {
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
