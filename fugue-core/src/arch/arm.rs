#[cfg(not(feature = "dynamic"))]
pub use fugue_lifter::arm::*;
use fugue_lifter::runtime::context::ContextBitRange;
use yaxpeax_arch::*;
use yaxpeax_arm::armv7::{DecodeError, InstDecoder, Instruction, Opcode, Operand, Reg};

use crate::arch::Arch;
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties, LazySymbol, Symbol};
use crate::lazy_symbol;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    ContextHint, ContextSet, Disassembler, DisassemblerError, Language, LanguageVariant, Lifter,
    LiftingContext,
};

static MAPPING_SYMBOL_ARM: LazySymbol = lazy_symbol!("$a");
static MAPPING_SYMBOL_THUMB: LazySymbol = lazy_symbol!("$t");
static MAPPING_SYMBOL_DATA: LazySymbol = lazy_symbol!("$d");

#[derive(Clone)]
struct Resolved {
    gprs: Vec<Varnode>,
    t_mode: ContextBitRange,
}

impl Resolved {
    fn for_language(language: &'static Language) -> Self {
        let reg = |name| language.register_by_name(name);

        let gprs = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
            "lr", "pc",
        ]
        .into_iter()
        .filter_map(reg)
        .collect();

        let t_mode = language
            .context_variable_by_name("TMode")
            .expect("ARM language must define TMode context variable");

        Self { gprs, t_mode }
    }
}

#[derive(Clone)]
pub struct Arm {
    language: LanguageVariant,
    is_thumb: bool,
    resolved: Resolved,
}

impl ArchT for Arm {
    fn dissassembler(&self) -> Disassembler {
        ArmDisassembler::new(self.is_thumb, self.resolved.t_mode)
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language.language())
    }

    fn canonicalise_address(&self, addr: Address) -> Option<(Address, ContextSet)> {
        let t_mode = (addr.offset() & 1) as u32;
        let alignment = if t_mode != 0 { 2 } else { 4 };
        let naddr = addr.wrap(self.language()).align(alignment);
        (naddr == addr).then_some((naddr, ContextSet::single(self.resolved.t_mode, t_mode)))
    }

    fn canonicalise_address_with(
        &self,
        addr: Address,
        context: &LiftingContext,
    ) -> Option<(Address, ContextSet)> {
        let t_mode = addr.offset() & 1 == 1
            || context.get_variable_by_bits(self.resolved.t_mode, addr.offset()) == 1;
        let alignment = if t_mode { 2 } else { 4 };
        let naddr = addr.wrap(self.language()).align(alignment);
        (naddr == addr).then_some((
            naddr,
            ContextSet::single(self.resolved.t_mode, t_mode as u32),
        ))
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        if self.is_thumb {
            let mut bytes = [0x70, 0x47];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(self.resolved.t_mode, 1))
        } else {
            let mut bytes = [0x1e, 0xff, 0x2f, 0xe1];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(self.resolved.t_mode, 0))
        }
    }

    fn gprs(&self) -> &[Varnode] {
        &self.resolved.gprs
    }

    fn resolve_mapping_symbol(&self, symbol: &Symbol) -> Option<ContextHint> {
        if symbol == &*MAPPING_SYMBOL_ARM {
            return Some(
                ContextHint::code().with_context(ContextSet::single(self.resolved.t_mode, 0)),
            );
        }

        if symbol == &*MAPPING_SYMBOL_THUMB {
            return Some(
                ContextHint::code().with_context(ContextSet::single(self.resolved.t_mode, 1)),
            );
        }

        if symbol == &*MAPPING_SYMBOL_DATA {
            return Some(ContextHint::data());
        }

        None
    }

    fn language_variant(&self) -> LanguageVariant {
        self.language
    }
}

impl Arm {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: LanguageVariant) -> Arch {
        let is_thumb = language.variant().ends_with("T");
        let resolved = Resolved::for_language(language.language());
        Arch::from(Box::new(Self {
            language,
            is_thumb,
            resolved,
        }) as Box<dyn ArchT>)
    }
}

struct ArmDisassembler {
    decoder: InstDecoder,
    t_mode: ContextBitRange,
}

impl ArmDisassembler {
    #[allow(clippy::new_ret_no_self)]
    fn new(thumb: bool, t_mode: ContextBitRange) -> Disassembler {
        Disassembler::new(Self {
            decoder: if thumb {
                InstDecoder::default_thumb()
            } else {
                InstDecoder::default()
            },
            t_mode,
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
    fn disassemble(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let in_thumb = context.get_variable_by_bits(self.t_mode, address.offset());

        self.decoder.set_thumb_mode(in_thumb == 1);

        let mut reader = yaxpeax_arch::U8Reader::new(bytes);
        let insn = match self.decoder.decode(&mut reader) {
            Ok(insn) => {
                let size = insn.len().to_const() as usize;
                let properties = if self.should_lift(&insn) {
                    InsnProperties::NEEDS_LIFTING
                } else {
                    let naddress = address + size;
                    context.set_variable_by_bits(self.t_mode, naddress.offset(), in_thumb);
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
