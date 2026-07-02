#[cfg(feature = "static-lifters")]
pub use fugue_lifter::arm::*;
use fugue_lifter::runtime::context::ContextBitRange;
use yaxpeax_arch::*;
use yaxpeax_arm::armv7::{DecodeError, InstDecoder, Instruction, Opcode, Operand, Reg};

use crate::arch::Arch;
use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::il::pcode::Varnode;
use crate::ir::{
    Address, ExternFunctionTemplate, Insn, InsnProperties, LazySymbol, RawAddress, Symbol,
};
use crate::lazy_symbol;
use crate::lifter::dynamic::LanguageSource;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    ContextHint, ContextSet, Disassembler, DisassemblerError, Language, LanguageError, LanguageId,
    LanguageLoader, Lifter, LiftingContext,
};

static MAPPING_SYMBOL_ARM: LazySymbol = lazy_symbol!("$a");
static MAPPING_SYMBOL_THUMB: LazySymbol = lazy_symbol!("$t");
static MAPPING_SYMBOL_DATA: LazySymbol = lazy_symbol!("$d");

#[derive(Clone)]
struct ArchData {
    gprs: Vec<Varnode>,
    t_mode: ContextBitRange,
}

impl ArchData {
    fn new(language: &'static Language) -> Self {
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
    language: &'static Language,
    is_thumb: bool,
    data: ArchData,
}

impl ArchT for Arm {
    fn disassembler(&self) -> Disassembler {
        ArmDisassembler::new(self.is_thumb, self.data.t_mode)
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn canonicalise_address(&self, addr: RawAddress) -> Option<(RawAddress, ContextSet)> {
        let t_mode = (addr.offset() & 1) as u32;
        let alignment = if t_mode != 0 { 2 } else { 4 };
        let cleared = RawAddress::from(addr.offset() & !1);
        let naddr = cleared.wrap(self.language()).align(alignment);
        (naddr == cleared).then_some((naddr, ContextSet::single(self.data.t_mode, t_mode)))
    }

    fn canonicalise_address_with(
        &self,
        addr: RawAddress,
        context: &LiftingContext,
    ) -> Option<(RawAddress, ContextSet)> {
        let t_mode = (addr.offset() & 1 == 1
            || context.get_variable_by_bits(self.data.t_mode, addr.offset()) == 1)
            as u32;
        let alignment = if t_mode != 0 { 2 } else { 4 };
        let cleared = RawAddress::from(addr.offset() & !1);
        let naddr = cleared.wrap(self.language()).align(alignment);
        (naddr == cleared).then_some((naddr, ContextSet::single(self.data.t_mode, t_mode)))
    }

    fn external_function_template(&self) -> ExternFunctionTemplate {
        if self.is_thumb {
            let mut bytes = [0x70, 0x47];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(self.data.t_mode, 1))
        } else {
            let mut bytes = [0x1e, 0xff, 0x2f, 0xe1];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternFunctionTemplate::new_with(bytes, ContextSet::single(self.data.t_mode, 0))
        }
    }

    fn gprs(&self) -> &[Varnode] {
        &self.data.gprs
    }

    fn resolve_mapping_symbol(&self, symbol: &Symbol) -> Option<ContextHint> {
        if symbol == &*MAPPING_SYMBOL_ARM {
            return Some(ContextHint::code().with_context(ContextSet::single(self.data.t_mode, 0)));
        }

        if symbol == &*MAPPING_SYMBOL_THUMB {
            return Some(ContextHint::code().with_context(ContextSet::single(self.data.t_mode, 1)));
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

impl Arm {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(language: &'static Language) -> Arch {
        let is_thumb = language.variant().ends_with("T");
        let data = ArchData::new(language);
        Arch::from(Box::new(Self {
            language,
            is_thumb,
            data,
        }) as Box<dyn ArchT>)
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
            None | Some("v8") => {
                return Ok(if is_be {
                    be::variants::V8
                } else {
                    le::variants::V8
                });
            }
            Some("v8T") => {
                return Ok(if is_be {
                    be::variants::V8T
                } else {
                    le::variants::V8T
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
            None | Some("v8") => {
                return Ok(if is_be {
                    be::variants::V8
                } else {
                    le::variants::V8
                });
            }
            Some("v8T") => {
                return Ok(if is_be {
                    be::variants::V8T
                } else {
                    le::variants::V8T
                });
            }
            _ => {}
        }
        let variant = variant.or(Some("v8"));
        let lid = LanguageId::new_with("ARM", is_be, 32, variant);
        Ok(loader.load(&lid)?)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "arm";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "ARM" && language.address_bits() == 32
    }

    fn create(language: &'static Language) -> Arch {
        Arm::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "arm";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "ARM" || id.bits() != 32 {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => Arm::resolve_variant_with(loader, id.is_big_endian(), id.variant())?,
            None => Arm::resolve_variant(id.is_big_endian(), id.variant())?,
        };

        Ok(Some(language))
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

#[cfg(all(test, feature = "static-lifters"))]
mod test {
    use super::Arm;
    use crate::ir::RawAddress;

    #[test]
    fn canonicalise_address_decodes_thumb_mode() {
        let language = Arm::resolve_default_variant(false).expect("arm language");
        let arch = Arm::new(language);

        let (thumb_entry, thumb_ctx) = arch
            .canonicalise_address(RawAddress::from(0x1001u64))
            .expect("odd thumb pointer canonicalises to its even entry");
        assert_eq!(thumb_entry, RawAddress::from(0x1000u64));

        let (arm_entry, arm_ctx) = arch
            .canonicalise_address(RawAddress::from(0x1000u64))
            .expect("4-aligned arm pointer canonicalises");
        assert_eq!(arm_entry, RawAddress::from(0x1000u64));

        assert_ne!(thumb_ctx, arm_ctx, "thumb and arm modes carry distinct context");

        assert!(
            arch.canonicalise_address(RawAddress::from(0x1002u64))
                .is_none(),
            "an even but not 4-aligned pointer is not a viable arm entry",
        );

        assert!(
            arch.canonicalise_address(RawAddress::from(0x1_0000_0001u64))
                .is_none(),
            "an out-of-space thumb pointer must be rejected, not silently wrapped",
        );
    }
}
