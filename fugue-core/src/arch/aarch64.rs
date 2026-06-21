#[cfg(feature = "static-lifters")]
pub use fugue_lifter::aarch64::*;
use yaxpeax_arch::*;
use yaxpeax_arm::armv8::a64::{DecodeError, InstDecoder, Instruction, Opcode};

use crate::arch::Arch;
use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties, LazySymbol, Symbol};
use crate::lazy_symbol;
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    ContextHint, Disassembler, DisassemblerError, Language, LanguageError, LanguageId,
    LanguageLoader, Lifter, LiftingContext,
};

static MAPPING_SYMBOL_CODE: LazySymbol = lazy_symbol!("$x");
static MAPPING_SYMBOL_DATA: LazySymbol = lazy_symbol!("$d");

#[derive(Clone)]
struct ArchData {
    gprs: Vec<Varnode>,
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
        let reg = |name| language.register_by_name(name);

        let gprs = [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x29", "x30",
        ]
        .into_iter()
        .filter_map(reg)
        .collect();

        Self { gprs }
    }
}

#[derive(Clone)]
pub struct AArch64 {
    language: &'static Language,
    data: ArchData,
}

impl ArchT for AArch64 {
    fn disassembler(&self) -> Disassembler {
        AArch64Disassembler::new()
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        ExternFunctionTemplate::new([0xc0, 0x03, 0x5f, 0xd6])
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        bytes == [0x00u8, 0x00u8, 0x00u8, 0x00u8]
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn resolve_mapping_symbol(&self, symbol: &Symbol) -> Option<ContextHint> {
        if symbol == &*MAPPING_SYMBOL_CODE {
            return Some(ContextHint::code());
        }

        if symbol == &*MAPPING_SYMBOL_DATA {
            return Some(ContextHint::data());
        }

        None
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl AArch64 {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let data = ArchData::new(language);
        Arch::from(Box::new(Self { language, data }) as Box<dyn ArchT>)
    }

    pub fn resolve_default_variant(is_be: bool) -> Result<&'static Language, LanguageError> {
        Self::resolve_variant(is_be, None)
    }

    pub fn resolve_variant<'a>(
        is_be: bool,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("v8A") => {
                return Ok(if is_be {
                    be::variants::V8A
                } else {
                    le::variants::V8A
                });
            }
            _ => {}
        }
        let loader = LanguageLoader::from_env()?;
        Self::resolve_variant_with(&loader, is_be, variant)
    }

    pub fn resolve_variant_with<'a>(
        loader: &LanguageLoader,
        is_be: bool,
        variant: impl Into<Option<&'a str>>,
    ) -> Result<&'static Language, LanguageError> {
        let variant = variant.into();
        #[cfg(feature = "static-lifters")]
        match variant {
            None | Some("v8A") => {
                return Ok(if is_be {
                    be::variants::V8A
                } else {
                    le::variants::V8A
                });
            }
            _ => {}
        }
        let variant = variant.or(Some("v8A"));
        let lid = LanguageId::new_with("AARCH64", is_be, 64, variant);
        Ok(loader.load(&lid)?)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "aarch64";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "AARCH64" && language.address_bits() == 64
    }

    fn create(language: &'static Language) -> Arch {
        AArch64::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "aarch64";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "AARCH64" || id.bits() != 64 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => {
                AArch64::resolve_variant_with(loader, id.is_big_endian(), id.variant())?
            }
            None => AArch64::resolve_variant(id.is_big_endian(), id.variant())?,
        };

        Ok(Some(language))
    }
}

struct AArch64Disassembler {
    decoder: InstDecoder,
}

impl AArch64Disassembler {
    #[allow(clippy::new_ret_no_self)]
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

impl DisassemblerT for AArch64Disassembler {
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
