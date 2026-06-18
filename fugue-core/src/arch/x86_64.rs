#[cfg(feature = "static-lifters")]
pub use fugue_lifter::x86_64::*;
use yaxpeax_arch::*;
use yaxpeax_x86::amd64::{DecodeError, InstDecoder, Instruction, Opcode};

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, Flag};
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties};
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    Disassembler, DisassemblerError, Language, LanguageError, LanguageId, LanguageLoader, Lifter,
    LiftingContext,
};

#[derive(Clone)]
struct ArchData {
    flags: Vec<Flag>,
    gprs: Vec<Varnode>,
    frame_pointer: Option<Varnode>,
    swi_op: Option<u16>,
    invalid_instruction_op: Option<u16>,
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
        let reg = |name| language.register_by_name(name);
        let flag = |name, ctor: fn(Varnode) -> Flag| reg(name).map(ctor);

        let flags = [
            flag("AF", Flag::a),
            flag("CF", Flag::c),
            flag("DF", Flag::new),
            flag("OF", Flag::v),
            flag("PF", Flag::p),
            flag("SF", Flag::n),
            flag("ZF", Flag::z),
        ]
        .into_iter()
        .flatten()
        .collect();

        let gprs = [
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
            "R12", "R13", "R14", "R15",
        ]
        .into_iter()
        .filter_map(reg)
        .collect();

        Self {
            flags,
            gprs,
            frame_pointer: reg("RBP"),
            swi_op: language.user_op_by_name("swi"),
            invalid_instruction_op: language.user_op_by_name("invalidInstructionException"),
        }
    }
}

#[derive(Clone)]
pub struct X86_64 {
    language: &'static Language,
    data: ArchData,
}

impl ArchT for X86_64 {
    fn disassembler(&self) -> Disassembler {
        X86_64Disassembler::new()
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        ExternFunctionTemplate::new([0xc3])
    }

    fn flags(&self) -> &[Flag] {
        &self.data.flags
    }

    fn frame_pointer(&self) -> Option<Varnode> {
        self.data.frame_pointer
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        const NONSENSE: &[&[u8]] = &[&[0x00u8, 0x00u8], &[0x00u8], &[0xf0u8]];
        NONSENSE.contains(&bytes)
    }

    fn is_skip_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(op) && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_instruction_op == Some(op)
    }

    fn is_trap_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(op) && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_instruction_op == Some(op)
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl X86_64 {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let data = ArchData::new(language);
        Arch::from(Box::new(Self { language, data }) as Box<dyn ArchT>)
    }

    pub fn resolve_default_variant() -> Result<&'static Language, LanguageError> {
        Self::resolve_variant(None)
    }

    pub fn resolve_variant<'a>(
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => return Ok(variants::DEFAULT),
            Some("compat32") => return Ok(variants::COMPAT32),
            _ => {}
        }
        let loader = LanguageLoader::from_env()?;
        Self::resolve_variant_with(&loader, variant)
    }

    pub fn resolve_variant_with<'a>(
        loader: &LanguageLoader,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("default") => return Ok(variants::DEFAULT),
            Some("compat32") => return Ok(variants::COMPAT32),
            _ => {}
        }
        let lid = LanguageId::new_with("x86", false, 64, variant);
        Ok(loader.load(&lid)?)
    }
}

fn supports_language(language: &'static Language) -> bool {
    language.processor() == "x86" && language.address_bits() == 64
}

fn provide_language(
    id: &LanguageId,
    source: &LanguageSource<'_>,
) -> Result<Option<&'static Language>, LanguageError> {
    if id.processor() != "x86" || id.bits() != 64 || id.is_big_endian() {
        return Ok(None);
    }

    let language = match source.loader() {
        Some(loader) => X86_64::resolve_variant_with(loader, id.variant())?,
        None => X86_64::resolve_variant(id.variant())?,
    };

    Ok(Some(language))
}

crate::registry::submit! {
    ArchProvider::new("x86-64", supports_language, X86_64::new)
}

crate::registry::submit! {
    LanguageProvider::new("x86-64", provide_language)
}

struct X86_64Disassembler {
    decoder: InstDecoder,
}

impl X86_64Disassembler {
    #[allow(clippy::new_ret_no_self)]
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

impl DisassemblerT for X86_64Disassembler {
    fn disassemble(
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
