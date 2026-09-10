#[cfg(feature = "static-lifters")]
pub use fugue_lifter::x86::*;
use memchr::arch::all::is_prefix;
use yaxpeax_arch::*;
use yaxpeax_x86::protected_mode::{DecodeError, InstDecoder, Instruction, Opcode};

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, BytesProperties, ExternalThunkTemplate, Flag};
use crate::ir::{Address, Insn, InsnProperties, RawAddress};
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    Disassembler, DisassemblerError, Language, LanguageError, LanguageId, LanguageLoader,
    LanguageSource, Lifter, LiftingContext, Varnode,
};

const ENTRY_INSNS: &[&[u8]] = &[&[0xf3, 0x0f, 0x1e, 0xfa], &[0xf3, 0x0f, 0x1e, 0xfb]];
const NONSENSE: &[&[u8]] = &[&[0x00, 0x00], &[0x00], &[0xf0]];
const NOP_INSNS: &[&[u8]] = &[
    &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x66, 0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x66, 0x90],
    &[0x90],
];
const PADDING: &[&[u8]] = &[&[0xcc]];

#[derive(Clone)]
struct ArchData {
    flags: Vec<Flag>,
    gprs: Vec<Varnode>,
    frame_pointer: Option<Varnode>,
    swi_op: Option<u16>,
    invalid_insn_op: Option<u16>,
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

        let gprs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"]
            .into_iter()
            .filter_map(reg)
            .collect();

        Self {
            flags,
            gprs,
            frame_pointer: reg("EBP"),
            swi_op: language.user_op_by_name("swi"),
            invalid_insn_op: language.user_op_by_name("invalidInstructionException"),
        }
    }
}

#[derive(Clone)]
pub struct X86 {
    language: &'static Language,
    data: ArchData,
}

impl ArchT for X86 {
    fn disassembler(&self) -> Disassembler {
        X86Disassembler::new()
    }

    fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }

    fn external_thunk_template(&self) -> ExternalThunkTemplate {
        ExternalThunkTemplate::new([0xc3])
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

    fn classify_bytes(&self, bytes: &[u8]) -> BytesProperties {
        let mut size = 0usize;
        let mut properties = BytesProperties::empty();

        while let Some(remaining) = bytes.get(size..) {
            let matched = ENTRY_INSNS
                .iter()
                .copied()
                .find(|pattern| is_prefix(remaining, pattern))
                .map(|pattern| (pattern, BytesProperties::ENTRY_INSN))
                .or_else(|| {
                    NONSENSE
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::NONSENSE))
                })
                .or_else(|| {
                    NOP_INSNS
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::NOP_INSN))
                })
                .or_else(|| {
                    PADDING
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::PADDING))
                });
            let Some((pattern, next_properties)) = matched else {
                break;
            };
            if !properties.is_empty()
                && properties != next_properties
                && !(properties.is_alignment() && next_properties.is_alignment())
            {
                break;
            }

            properties |= next_properties;
            size += pattern.len();
        }

        if size != 0 && size == bytes.len() {
            properties
        } else {
            BytesProperties::empty()
        }
    }

    fn classify_contiguous_bytes(
        &self,
        _address: RawAddress,
        _context: &LiftingContext,
        bytes: &[u8],
    ) -> (usize, BytesProperties) {
        let mut size = 0usize;
        let mut properties = BytesProperties::empty();

        while let Some(remaining) = bytes.get(size..) {
            let matched = ENTRY_INSNS
                .iter()
                .copied()
                .find(|pattern| is_prefix(remaining, pattern))
                .map(|pattern| (pattern, BytesProperties::ENTRY_INSN))
                .or_else(|| {
                    NONSENSE
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::NONSENSE))
                })
                .or_else(|| {
                    NOP_INSNS
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::NOP_INSN))
                })
                .or_else(|| {
                    PADDING
                        .iter()
                        .copied()
                        .find(|pattern| is_prefix(remaining, pattern))
                        .map(|pattern| (pattern, BytesProperties::PADDING))
                });
            let Some((pattern, next_properties)) = matched else {
                break;
            };
            if !properties.is_empty()
                && properties != next_properties
                && !(properties.is_alignment() && next_properties.is_alignment())
            {
                break;
            }

            properties |= next_properties;
            size += pattern.len();
        }

        (size, properties)
    }

    fn is_skip_intrinsic(&self, user_op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(user_op)
            && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_insn_op == Some(user_op)
    }

    fn is_trap_intrinsic(&self, user_op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(user_op)
            && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_insn_op == Some(user_op)
    }

    fn language(&self) -> &'static Language {
        self.language
    }
}

impl X86 {
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
            _ => {}
        }
        let lid = LanguageId::new_with("x86", false, 32, variant);
        loader.load(&lid)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "x86";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "x86" && language.address_bits() == 32
    }

    fn create(language: &'static Language) -> Arch {
        X86::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "x86";

    fn provide(
        id: &LanguageId,
        source: &LanguageSource<'_>,
    ) -> Result<Option<&'static Language>, LanguageError> {
        if id.processor() != "x86" || id.bits() != 32 || id.is_big_endian() {
            return Ok(None);
        }

        let language = match source.loader() {
            Some(loader) => X86::resolve_variant_with(loader, id.variant())?,
            None => X86::resolve_variant(id.variant())?,
        };

        Ok(Some(language))
    }
}

struct X86Disassembler {
    decoder: InstDecoder,
}

impl X86Disassembler {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Disassembler {
        Disassembler::new(Self {
            decoder: InstDecoder::default(),
        })
    }

    fn should_lift(insn: &Instruction) -> bool {
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
                | Opcode::JECXZ
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

impl DisassemblerT for X86Disassembler {
    fn disassemble(
        &mut self,
        address: Address,
        bytes: &[u8],
        _context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let mut reader = U8Reader::new(bytes);
        let insn = match self.decoder.decode(&mut reader) {
            Ok(insn) => {
                let size = insn.len().to_const() as usize;
                Insn::from_disassembly(
                    address,
                    size,
                    if Self::should_lift(&insn) {
                        InsnProperties::NEEDS_FLOW_RESOLUTION
                    } else {
                        InsnProperties::FALL_THROUGH
                    },
                )?
            }
            Err(DecodeError::IncompleteDecoder) => {
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
    use super::X86;
    use crate::arch::BytesProperties;
    use crate::ir::RawAddress;

    #[test]
    fn test_byte_patterns_are_classified() {
        let language = X86::resolve_default_variant().expect("x86 language");
        let arch = X86::new(language);
        let lifter = arch.lifter();

        for entry in [
            [0xf3u8, 0x0f, 0x1e, 0xfa].as_slice(),
            &[0xf3, 0x0f, 0x1e, 0xfb],
        ] {
            let properties = arch.classify_bytes(entry);
            assert!(properties.is_entry_insn());
            assert!(!properties.is_alignment());
        }

        for nop in [
            [0x90u8].as_slice(),
            &[0x66, 0x90],
            &[0x0f, 0x1f, 0x00],
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            let properties = arch.classify_bytes(nop);
            assert!(properties.is_nop_insn(), "{nop:02x?} should be a NOP");
            assert!(properties.is_alignment());
            assert!(!properties.is_padding());
        }

        let padding = arch.classify_bytes(&[0xcc]);
        assert!(padding.is_padding());
        assert!(padding.is_alignment());
        assert!(!padding.is_nop_insn());

        for nonsense in [[0x00u8].as_slice(), &[0x00, 0x00], &[0xf0]] {
            assert!(arch.classify_bytes(nonsense).is_nonsense());
        }

        assert_eq!(
            arch.classify_contiguous_bytes(
                RawAddress::from(0u64),
                lifter.context(),
                &[0x90, 0x66, 0x90, 0x55],
            ),
            (3, BytesProperties::NOP_INSN)
        );
        assert_eq!(
            arch.classify_contiguous_bytes(
                RawAddress::from(0u64),
                lifter.context(),
                &[0x90, 0xcc, 0x55],
            ),
            (2, BytesProperties::ALIGNMENT)
        );
        assert_eq!(
            arch.classify_contiguous_bytes(
                RawAddress::from(0u64),
                lifter.context(),
                &[0x00, 0x00, 0xf0, 0x90],
            ),
            (3, BytesProperties::NONSENSE)
        );
        assert!(arch.classify_bytes(&[0x55, 0x48, 0x89, 0xe5]).is_empty());
        assert!(arch.classify_bytes(&[]).is_empty());
    }
}
