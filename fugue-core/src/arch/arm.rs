use yaxpeax_arch::*;
use yaxpeax_arm::armv7::{DecodeError, InstDecoder, Instruction, Opcode, Operand, Reg};

use fugue_lifter::arm::context::T_MODE;
use fugue_lifter::arm::register::{
    LR, PC, R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP,
};
pub use fugue_lifter::arm::*;

use crate::arch::Arch;
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties};
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    ContextSet, Disassembler, DisassemblerError, LanguageVariant, Lifter, LiftingContext,
};

const GPRS: &[Varnode] = &[
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP, LR, PC,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Arm {
    language: LanguageVariant,
    is_thumb: bool,
}

impl ArchT for Arm {
    fn dissassembler(&self) -> Disassembler {
        ArmDisassembler::new(self.is_thumb)
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language(), self.language.context()())
    }

    fn canonicalise_address(&self, addr: Address) -> Option<(Address, ContextSet)> {
        let t_mode = (addr.offset() & 1) as u32;
        let alignment = if t_mode != 0 { 2 } else { 4 };
        let naddr = addr.wrap_and_align_with(self.language(), alignment);
        (naddr == addr).then_some((naddr, ContextSet::single(T_MODE, t_mode)))
    }

    fn canonicalise_address_with(
        &self,
        addr: Address,
        context: &LiftingContext,
    ) -> Option<(Address, ContextSet)> {
        let t_mode =
            addr.offset() & 1 == 1 || context.get_variable_by_bits(T_MODE, addr.into()) == 1;
        let alignment = if t_mode { 2 } else { 4 };
        let naddr = addr.wrap_and_align_with(self.language(), alignment);
        (naddr == addr).then_some((naddr, ContextSet::single(T_MODE, t_mode as u32)))
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        if self.is_thumb {
            let mut bytes = [0x70, 0x47];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(T_MODE, 1))
        } else {
            let mut bytes = [0x1e, 0xff, 0x2f, 0xe1];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(T_MODE, 0))
        }
    }

    fn gprs(&self) -> &[Varnode] {
        GPRS
    }

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl Arm {
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        let is_thumb = language.variant().ends_with("T");
        Arch::from(Box::new(Self { language, is_thumb }) as Box<dyn ArchT>)
    }
}

struct ArmDisassembler {
    decoder: InstDecoder,
}

impl ArmDisassembler {
    fn new(thumb: bool) -> Disassembler {
        Disassembler::new(Self {
            decoder: if thumb {
                InstDecoder::default_thumb()
            } else {
                InstDecoder::default()
            },
        })
    }

    fn should_lift(&self, insn: &Instruction) -> bool {
        let pc = Reg::from_u8(15);

        match insn.opcode {
            Opcode::B
            | Opcode::BL
            | Opcode::BLX
            | Opcode::BX
            | Opcode::BXJ
            | Opcode::BKPT
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::ERET
            | Opcode::HVC
            | Opcode::IT
            | Opcode::RFE(_, _)
            | Opcode::SVC
            | Opcode::SMC
            | Opcode::UDF => true,
            Opcode::MVN | Opcode::MOV => insn.operands[0] == Operand::Reg(pc),
            _ => false,
        }
    }
}

impl DisassemblerT for ArmDisassembler {
    fn disassemble_insn(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let in_thumb = context.get_variable_by_bits(T_MODE, address.into());

        self.decoder.set_thumb_mode(in_thumb == 1);

        let mut reader = yaxpeax_arch::U8Reader::new(bytes);
        let insn = match self.decoder.decode(&mut reader) {
            Ok(insn) => {
                let size = insn.len().to_const() as usize;
                let properties = if self.should_lift(&insn) {
                    InsnProperties::NEEDS_LIFTING
                } else {
                    // NOTE: we propagate the T_MODE variable to the next instruction
                    // mimicking the behaviour of the language spec.
                    let naddress = address + size;
                    context.set_variable_by_bits(T_MODE, naddress.into(), in_thumb);
                    InsnProperties::FALL
                };

                Insn::from_disassembly(address, size, properties)
            }
            Err(DecodeError::Incomplete) => {
                Insn::from_disassembly(address, 0, InsnProperties::NEEDS_LIFTING)
            }
            Err(e) => {
                return Err(DisassemblerError::disassembler(e));
            }
        };
        Ok(insn)
    }
}
