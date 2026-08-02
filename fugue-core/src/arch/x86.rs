#[cfg(feature = "static-lifters")]
pub use fugue_lifter::x86::*;
use yaxpeax_arch::*;
use yaxpeax_x86::protected_mode::{DecodeError, InstDecoder, Instruction, Opcode};

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, BytesProperties, Flag};
use crate::ir::{Address, ExternFunctionTemplate, Insn, InsnProperties, RawAddress};
use crate::lifter::LanguageSource;
use crate::lifter::traits::Disassembler as DisassemblerT;
use crate::lifter::{
    Disassembler, DisassemblerError, Language, LanguageError, LanguageId, LanguageLoader, Lifter,
    LiftingContext, Varnode,
};

fn classify_bytes(bytes: &[u8]) -> BytesProperties {
    const NONSENSE: &[&[u8]] = &[&[0x00u8, 0x00u8], &[0x00u8], &[0xf0u8]];
    const ENTRY_MARKERS: &[&[u8]] = &[
        &[0xf3u8, 0x0fu8, 0x1eu8, 0xfau8],
        &[0xf3u8, 0x0fu8, 0x1eu8, 0xfbu8],
    ];

    let mut properties = BytesProperties::empty();

    if bytes.is_empty() {
        return properties;
    }

    if ENTRY_MARKERS.contains(&bytes) {
        properties |= BytesProperties::ENTRY_MARKER;
    }

    if NONSENSE.contains(&bytes) {
        properties |= BytesProperties::NONSENSE;
    }

    let padded = bytes.iter().all(|&byte| byte == 0xcc)
        || bytes
            .iter()
            .position(|byte| !matches!(byte, 0x66 | 0x2e))
            .is_some_and(|opcode| matches!(&bytes[opcode..], [0x90] | [0x0f, 0x1f, ..]));

    if padded {
        properties |= BytesProperties::PADDING;
    }

    properties
}

fn classify_contiguous_bytes(bytes: &[u8]) -> (usize, BytesProperties) {
    let decoder = InstDecoder::default();
    let mut size = 0usize;
    let mut properties = BytesProperties::empty();

    while let Some(remaining) = bytes.get(size..) {
        let mut reader = U8Reader::new(remaining);
        let Ok(insn) = decoder.decode(&mut reader) else {
            break;
        };
        let insn_size = insn.len().to_const() as usize;
        if insn_size == 0 {
            break;
        }
        let Some(insn_bytes) = remaining.get(..insn_size) else {
            break;
        };
        let insn_properties = classify_bytes(insn_bytes);
        if insn_properties.is_empty() || (!properties.is_empty() && insn_properties != properties) {
            break;
        }

        properties = insn_properties;
        size += insn_size;
    }

    (size, properties)
}
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

    fn classify_bytes(&self, bytes: &[u8]) -> BytesProperties {
        classify_bytes(bytes)
    }

    fn classify_contiguous_bytes(
        &self,
        _address: RawAddress,
        _context: &LiftingContext,
        bytes: &[u8],
    ) -> (usize, BytesProperties) {
        classify_contiguous_bytes(bytes)
    }

    fn is_skip_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(op) && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_insn_op == Some(op)
    }

    fn is_trap_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        (self.data.swi_op == Some(op) && args.first().copied() == Some(Varnode::constant(0x3, 8)))
            || self.data.invalid_insn_op == Some(op)
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
                    if self.should_lift(&insn) {
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
    use super::*;

    #[test]
    fn test_byte_patterns_are_classified() {
        for padding in [
            [0x90u8].as_slice(),
            &[0x66, 0x90],
            &[0x0f, 0x1f, 0x00],
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0xcc],
        ] {
            assert!(
                classify_bytes(padding).is_padding(),
                "{padding:02x?} should be padding"
            );
        }

        for marker in [
            [0xf3u8, 0x0f, 0x1e, 0xfa].as_slice(),
            &[0xf3, 0x0f, 0x1e, 0xfb],
        ] {
            let properties = classify_bytes(marker);
            assert!(properties.is_entry_marker(), "{marker:02x?} marks an entry");
            assert!(!properties.is_padding(), "{marker:02x?} is not padding");
        }

        for nonsense in [[0x00u8].as_slice(), &[0x00, 0x00], &[0xf0]] {
            assert!(classify_bytes(nonsense).is_nonsense());
        }

        assert!(classify_bytes(&[0x55, 0x48, 0x89, 0xe5]).is_empty());
        assert!(classify_bytes(&[]).is_empty());
    }
}
