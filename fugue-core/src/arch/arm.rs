use fugue_bytes::{BE, ByteCast, Endian, LE};
#[cfg(feature = "static-lifters")]
pub use fugue_lifter::arm::*;
use fugue_lifter::runtime::context::ContextBitRange;
use memchr::arch::all::is_prefix;
use yaxpeax_arch::{Decoder as _, LengthedInstruction as _, U8Reader};
use yaxpeax_arm::armv7::{
    ConditionCode, DecodeError, InstDecoder, Instruction, Opcode, Operand, Reg,
};

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, BytesProperties, ExternalThunkTemplate};
use crate::ir::{Address, Insn, InsnError, InsnProperties, LazySymbol, RawAddress, Symbol};
use crate::lazy_symbol;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    ContextHint, ContextSet, Disassembler, DisassemblerError, Language, LanguageError, LanguageId,
    LanguageLoader, LanguageSource, Lifter, LiftingContext, Varnode,
};

static MAPPING_SYMBOL_ARM: LazySymbol = lazy_symbol!("$a");
static MAPPING_SYMBOL_THUMB: LazySymbol = lazy_symbol!("$t");
static MAPPING_SYMBOL_DATA: LazySymbol = lazy_symbol!("$d");

const ARM_NOP_INSNS_BE: &[&[u8]] = &[&[0xe3, 0x20, 0xf0, 0x00], &[0xe1, 0xa0, 0x00, 0x00]];
const ARM_NOP_INSNS_LE: &[&[u8]] = &[&[0x00, 0xf0, 0x20, 0xe3], &[0x00, 0x00, 0xa0, 0xe1]];
const THUMB_NOP_INSNS_BE: &[&[u8]] = &[&[0xf3, 0xaf, 0x80, 0x00], &[0xbf, 0x00], &[0x46, 0xc0]];
const THUMB_NOP_INSNS_LE: &[&[u8]] = &[&[0xaf, 0xf3, 0x00, 0x80], &[0x00, 0xbf], &[0xc0, 0x46]];

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
        ArmDisassembler::new(self.is_thumb, self.endian(), self.data.t_mode)
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn canonicalise_address(&self, addr: RawAddress) -> Option<(RawAddress, ContextSet)> {
        let t_mode = (addr.offset() & 1) as u32;
        self.canonicalise_with_mode(addr, t_mode)
    }

    fn canonicalise_address_with(
        &self,
        addr: RawAddress,
        context: &LiftingContext,
    ) -> Option<(RawAddress, ContextSet)> {
        let t_mode = (addr.offset() & 1 == 1
            || context.get_variable_by_bits(self.data.t_mode, addr.offset()) == 1)
            as u32;
        self.canonicalise_with_mode(addr, t_mode)
    }

    fn classify_bytes(&self, bytes: &[u8]) -> BytesProperties {
        let arm = Self::nop_insn_size(bytes, self.language().is_big_endian(), false);
        let thumb = Self::nop_insn_size(bytes, self.language().is_big_endian(), true);
        if (arm != 0 && arm == bytes.len()) || (thumb != 0 && thumb == bytes.len()) {
            BytesProperties::NOP_INSN
        } else {
            BytesProperties::empty()
        }
    }

    fn classify_contiguous_bytes(
        &self,
        address: RawAddress,
        context: &LiftingContext,
        bytes: &[u8],
    ) -> (usize, BytesProperties) {
        let thumb = context.get_variable_by_bits(self.data.t_mode, address.offset()) == 1;
        let size = Self::nop_insn_size(bytes, self.language().is_big_endian(), thumb);
        (
            size,
            if size == 0 {
                BytesProperties::empty()
            } else {
                BytesProperties::NOP_INSN
            },
        )
    }

    fn external_thunk_template(&self) -> ExternalThunkTemplate {
        if self.is_thumb {
            let mut bytes = [0x70, 0x47];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternalThunkTemplate::new_with(bytes, ContextSet::single(self.data.t_mode, 1))
        } else {
            let mut bytes = [0x1e, 0xff, 0x2f, 0xe1];
            if self.language().is_big_endian() {
                bytes.reverse();
            }
            ExternalThunkTemplate::new_with(bytes, ContextSet::single(self.data.t_mode, 0))
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
        loader.load(&lid)
    }

    fn canonicalise_with_mode(
        &self,
        address: RawAddress,
        t_mode: u32,
    ) -> Option<(RawAddress, ContextSet)> {
        let alignment = if t_mode != 0 { 2 } else { 4 };
        let cleared = address.align_down(2);
        let canonical = cleared.wrap_and_align_with(self.language(), alignment);
        (canonical == cleared).then_some((canonical, ContextSet::single(self.data.t_mode, t_mode)))
    }

    fn nop_insn_size(bytes: &[u8], big_endian: bool, thumb: bool) -> usize {
        let patterns = match (big_endian, thumb) {
            (false, false) => ARM_NOP_INSNS_LE,
            (false, true) => THUMB_NOP_INSNS_LE,
            (true, false) => ARM_NOP_INSNS_BE,
            (true, true) => THUMB_NOP_INSNS_BE,
        };
        let mut size = 0usize;

        while let Some(remaining) = bytes.get(size..) {
            let Some(pattern) = patterns
                .iter()
                .copied()
                .find(|pattern| is_prefix(remaining, pattern))
            else {
                break;
            };
            size += pattern.len();
        }

        size
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
    endian: Endian,
    t_mode: ContextBitRange,
}

impl ArmDisassembler {
    #[allow(clippy::new_ret_no_self)]
    fn new(is_thumb: bool, endian: Endian, t_mode: ContextBitRange) -> Disassembler {
        Disassembler::new(Self {
            decoder: if is_thumb {
                InstDecoder::default_thumb()
            } else {
                InstDecoder::default()
            },
            endian,
            t_mode,
        })
    }

    fn arm_definitely_falls_through(word: u32) -> bool {
        if word >> 28 == 0b1111 {
            return false;
        }

        let class = (word >> 25) & 0b111;
        let opcode = (word >> 21) & 0b1111;
        let set_flags = word & (1 << 20) != 0;
        let first_operand = (word >> 16) & 0b1111;
        let destination = (word >> 12) & 0b1111;
        match class {
            0b000 if word & (1 << 4) == 0 => match opcode {
                0..=7 | 12 | 14 => destination != 15,
                8..=11 => set_flags && destination == 0,
                13 | 15 => first_operand == 0 && destination != 15,
                _ => false,
            },
            0b001 => match opcode {
                0..=7 | 12 | 14 => destination != 15,
                8..=11 => set_flags && destination == 0,
                13 | 15 => first_operand == 0 && destination != 15,
                _ => false,
            },
            0b010 => destination != 15,
            0b011 => word & (1 << 4) == 0 && destination != 15,
            0b100 => word & (1 << 20) == 0 || word & (1 << 15) == 0,
            _ => false,
        }
    }

    fn should_lift(insn: &Instruction) -> bool {
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
            | Opcode::TBB
            | Opcode::TBH
            | Opcode::UDF => true,
            Opcode::AND
            | Opcode::EOR
            | Opcode::SUB
            | Opcode::RSB
            | Opcode::ADD
            | Opcode::ADC
            | Opcode::SBC
            | Opcode::RSC
            | Opcode::ORR
            | Opcode::MOV
            | Opcode::BIC
            | Opcode::MVN
            | Opcode::LSL
            | Opcode::LSR
            | Opcode::ASR
            | Opcode::RRX
            | Opcode::ROR
            | Opcode::ORN
            | Opcode::LDR => insn.operands[0] == Operand::Reg(pc),
            Opcode::POP => {
                matches!(insn.operands[0], Operand::RegList(list) if list & (1u16 << pc.number()) != 0)
            }
            Opcode::LDM(_, _, _, _) => {
                matches!(insn.operands[1], Operand::RegList(list) if list & (1u16 << pc.number()) != 0)
            }
            _ => false,
        }
    }

    fn resolve_arm_direct_flow(
        address: Address,
        insn: &Instruction,
        size: usize,
    ) -> Result<Option<Insn>, InsnError> {
        match insn.opcode {
            Opcode::B | Opcode::BL => {
                let Operand::BranchOffset(offset) = insn.operands[0] else {
                    return Ok(None);
                };
                let target = Address::new(
                    address.space(),
                    address.offset().wrapping_add_signed(i64::from(offset) << 2),
                );
                if insn.opcode == Opcode::B {
                    Insn::from_direct_branch(
                        address,
                        size,
                        target,
                        insn.condition != ConditionCode::AL,
                    )
                } else {
                    Insn::from_direct_call(address, size, target)
                }
                .map(Some)
            }
            _ if insn.condition != ConditionCode::AL => Ok(None),
            Opcode::BLX if matches!(insn.operands[0], Operand::Reg(_)) => {
                Insn::from_indirect_call(address, size).map(Some)
            }
            Opcode::BX => {
                let Operand::Reg(register) = insn.operands[0] else {
                    return Ok(None);
                };
                if register == Reg::from_u8(14) {
                    Insn::from_return(address, size)
                } else {
                    Insn::from_indirect_branch(address, size)
                }
                .map(Some)
            }
            Opcode::AND
            | Opcode::EOR
            | Opcode::SUB
            | Opcode::RSB
            | Opcode::ADD
            | Opcode::ADC
            | Opcode::SBC
            | Opcode::RSC
            | Opcode::ORR
            | Opcode::MOV
            | Opcode::BIC
            | Opcode::MVN
            | Opcode::LSL
            | Opcode::LSR
            | Opcode::ASR
            | Opcode::RRX
            | Opcode::ROR
            | Opcode::ORN
            | Opcode::LDR
                if insn.operands[0] == Operand::Reg(Reg::from_u8(15)) =>
            {
                Insn::from_indirect_branch(address, size).map(Some)
            }
            _ => Ok(None),
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
        let arm_word = bytes.get(..u32::SIZEOF).map(|bytes| match self.endian {
            Endian::Big => u32::read_bytes::<BE>(bytes),
            Endian::Little => u32::read_bytes::<LE>(bytes),
        });

        if in_thumb == 0 && arm_word.is_some_and(Self::arm_definitely_falls_through) {
            return Ok(Insn::from_disassembly(
                address,
                4,
                InsnProperties::FALL_THROUGH,
            )?);
        }

        self.decoder.set_thumb_mode(in_thumb == 1);

        let mut reader = U8Reader::new(bytes);
        let insn = match self.decoder.decode(&mut reader) {
            Ok(insn) => {
                let size = insn.len().to_const() as usize;
                if !insn.thumb
                    && let Some(resolved) = Self::resolve_arm_direct_flow(address, &insn, size)?
                {
                    return Ok(resolved);
                }
                let properties = if Self::should_lift(&insn) {
                    InsnProperties::NEEDS_FLOW_RESOLUTION
                } else {
                    InsnProperties::FALL_THROUGH
                };

                Insn::from_disassembly(address, size, properties)?
            }
            Err(DecodeError::Incomplete) => {
                Insn::from_disassembly(address, 0, InsnProperties::NEEDS_FLOW_RESOLUTION)?
            }
            Err(e) => {
                return Err(DisassemblerError::disassembler(e));
            }
        };
        Ok(insn)
    }
}

#[cfg(test)]
mod test {
    use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
    use yaxpeax_arm::armv7::InstDecoder;

    use super::{Arm, ArmDisassembler};
    use crate::arch::BytesProperties;
    use crate::ir::{Address, Insn, RawAddress};

    fn assert_direct_flow_matches_lifter(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let language = Arm::resolve_default_variant(false)?;
        let arch = Arm::new(language);
        let address = Address::in_default_space(0x1000u64);
        let mut disassembly_context = arch.lifter();
        let mut disassembler = arch.disassembler();
        let direct = disassembler.disassemble(address, bytes, disassembly_context.context_mut())?;

        let mut lifter = arch.lifter();
        let mut operations = Vec::new();
        let size = lifter.lift(address, bytes, &mut operations)?;
        let lifted = Insn::from_resolved_flow(language, address, size, &operations)?;

        assert_eq!(
            direct.properties(),
            lifted.properties(),
            "flow properties differ for {bytes:02x?}",
        );
        assert_eq!(
            direct.flow_targets().collect::<Vec<_>>(),
            lifted.flow_targets().collect::<Vec<_>>(),
            "flow targets differ for {bytes:02x?}",
        );
        Ok(())
    }

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

        assert_ne!(
            thumb_ctx, arm_ctx,
            "thumb and arm modes carry distinct context"
        );

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

    #[test]
    fn contiguous_nop_insns_respect_arm_mode() {
        let language = Arm::resolve_default_variant(false).expect("arm language");
        let arch = Arm::new(language);
        let address = Address::in_default_space(0x1000u64);
        let mut lifter = arch.lifter();

        let (size, properties) = arch.classify_contiguous_bytes(
            address.raw_address(),
            lifter.context(),
            &[0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0xa0, 0xe1, 0x01],
        );
        assert_eq!(size, 8);
        assert_eq!(properties, BytesProperties::NOP_INSN);

        let (_, thumb) = arch
            .canonicalise_address(RawAddress::from(0x1001u64))
            .expect("thumb address canonicalises");
        thumb.apply(address, lifter.context_mut());
        let (size, properties) = arch.classify_contiguous_bytes(
            address.raw_address(),
            lifter.context(),
            &[0x00, 0xbf, 0xc0, 0x46, 0x01],
        );
        assert_eq!(size, 4);
        assert_eq!(properties, BytesProperties::NOP_INSN);
    }

    #[test]
    fn direct_arm_branches_match_lifted_flow() -> Result<(), Box<dyn std::error::Error>> {
        assert_direct_flow_matches_lifter(&[0x00, 0x00, 0x00, 0xea])?;
        assert_direct_flow_matches_lifter(&[0x00, 0x00, 0x00, 0x1a])?;
        assert_direct_flow_matches_lifter(&[0x00, 0x00, 0x00, 0xeb])?;
        Ok(())
    }

    #[test]
    fn direct_arm_indirect_flows_match_lifted_flow() -> Result<(), Box<dyn std::error::Error>> {
        assert_direct_flow_matches_lifter(&[0x1e, 0xff, 0x2f, 0xe1])?;
        assert_direct_flow_matches_lifter(&[0x10, 0xff, 0x2f, 0xe1])?;
        assert_direct_flow_matches_lifter(&[0x30, 0xff, 0x2f, 0xe1])?;
        assert_direct_flow_matches_lifter(&[0x00, 0xf0, 0x9f, 0xe5])?;
        assert_direct_flow_matches_lifter(&[0x00, 0xf0, 0x8f, 0xe0])?;
        Ok(())
    }

    #[test]
    fn arm_fall_through_fast_path_excludes_control_flow() {
        for word in [
            0xea00_0000,
            0xe12f_ff1e,
            0xe59f_f000,
            0xe8bd_8000,
            0xe7f0_00f0,
            0xf000_0000,
        ] {
            assert!(
                !ArmDisassembler::arm_definitely_falls_through(word),
                "{word:08x} must use the decoder",
            );
        }
    }

    #[test]
    fn arm_fall_through_fast_path_accepts_regular_instructions() {
        for word in [
            0xe1a0_0000,
            0xe280_0001,
            0xe240_0001,
            0xe590_1000,
            0xe580_1000,
            0xe8b0_000e,
        ] {
            assert!(
                ArmDisassembler::arm_definitely_falls_through(word),
                "{word:08x} should bypass the decoder",
            );
        }
    }

    #[test]
    fn arm_fall_through_fast_path_matches_decoder_samples() {
        let decoder = InstDecoder::default();
        let mut state = 0x6d2b_79f5u32;

        for _ in 0..250_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if !ArmDisassembler::arm_definitely_falls_through(state) {
                continue;
            }

            let bytes = state.to_le_bytes();
            let instruction = decoder
                .decode(&mut U8Reader::new(&bytes))
                .unwrap_or_else(|error| panic!("{state:08x} did not decode: {error}"));
            assert_eq!(instruction.len().to_const(), 4);
            assert!(
                !ArmDisassembler::should_lift(&instruction),
                "{state:08x} decoded as flow: {instruction}",
            );
        }
    }
}
