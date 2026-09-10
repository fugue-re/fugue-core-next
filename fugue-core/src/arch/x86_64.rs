#[cfg(feature = "static-lifters")]
pub use fugue_lifter::x86_64::*;
use memchr::arch::all::is_prefix;
use yaxpeax_arch::*;
use yaxpeax_x86::amd64::{DecodeError, InstDecoder, Instruction, Opcode, Operand};

use crate::arch::registry::{ArchProvider, LanguageProvider};
use crate::arch::traits::Arch as ArchT;
use crate::arch::{Arch, BytesProperties, ExternalThunkTemplate, Flag};
use crate::ir::{Address, Insn, InsnError, InsnProperties, RawAddress};
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
            invalid_insn_op: language.user_op_by_name("invalidInstructionException"),
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
        loader.load(&lid)
    }
}

#[fugue_core::extension]
impl ArchProvider {
    const NAME: &str = "x86-64";

    fn supports(language: &'static Language) -> bool {
        language.processor() == "x86" && language.address_bits() == 64
    }

    fn create(language: &'static Language) -> Arch {
        X86_64::new(language)
    }
}

#[fugue_core::extension]
impl LanguageProvider {
    const NAME: &str = "x86-64";

    fn provide(
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
}

struct X86_64Disassembler {
    decoder: InstDecoder,
    insn: Instruction,
}

impl X86_64Disassembler {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Disassembler {
        Disassembler::new(Self {
            decoder: InstDecoder::default(),
            insn: Instruction::default(),
        })
    }

    fn relative_target(address: Address, size: usize, operand: &Operand) -> Option<Address> {
        let displacement = match operand {
            Operand::ImmediateI8 { imm } => i64::from(*imm),
            Operand::ImmediateI32 { imm } => i64::from(*imm),
            _ => return None,
        };
        let offset = address
            .offset()
            .wrapping_add(size as u64)
            .wrapping_add_signed(displacement);
        Some(Address::new(address.space(), offset))
    }

    fn resolve_control_flow(
        address: Address,
        insn: &Instruction,
        size: usize,
    ) -> Result<Option<Insn>, InsnError> {
        let opcode = insn.opcode();

        if opcode.is_jcc()
            || matches!(
                opcode,
                Opcode::LOOPNZ | Opcode::LOOPZ | Opcode::LOOP | Opcode::JRCXZ | Opcode::JECXZ
            )
        {
            let operand = insn.operand(0);
            let target = Self::relative_target(address, size, &operand);
            return target
                .map(|target| Insn::from_direct_branch(address, size, target, true))
                .transpose();
        }

        match opcode {
            Opcode::JMP | Opcode::CALL => {
                let operand = insn.operand(0);
                let target = Self::relative_target(address, size, &operand);
                match (opcode, target) {
                    (Opcode::JMP, Some(target)) => {
                        Insn::from_direct_branch(address, size, target, false)
                    }
                    (Opcode::JMP, None) if matches!(operand, Operand::Register { .. }) => {
                        Insn::from_indirect_branch(address, size)
                    }
                    (Opcode::CALL, Some(target)) => Insn::from_direct_call(address, size, target),
                    (Opcode::CALL, None) if matches!(operand, Operand::Register { .. }) => {
                        Insn::from_indirect_call(address, size)
                    }
                    _ => return Ok(None),
                }
            }
            Opcode::RETURN => Insn::from_return(address, size),
            _ => return Ok(None),
        }
        .map(Some)
    }

    fn should_lift(insn: &Instruction) -> bool {
        let opcode = insn.opcode();
        opcode.is_jcc()
            || matches!(
                opcode,
                Opcode::JMP
                    | Opcode::JMPF
                    | Opcode::JMPE
                    | Opcode::LOOPNZ
                    | Opcode::LOOPZ
                    | Opcode::LOOP
                    | Opcode::JRCXZ
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

impl DisassemblerT for X86_64Disassembler {
    fn disassemble(
        &mut self,
        address: Address,
        bytes: &[u8],
        _context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let mut reader = U8Reader::new(bytes);
        let insn = match self.decoder.decode_into(&mut self.insn, &mut reader) {
            Ok(()) => {
                let size = self.insn.len().to_const() as usize;
                if let Some(resolved) = Self::resolve_control_flow(address, &self.insn, size)? {
                    return Ok(resolved);
                }
                Insn::from_disassembly(
                    address,
                    size,
                    if Self::should_lift(&self.insn) {
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
    use std::error::Error;

    use super::X86_64;
    use crate::arch::BytesProperties;
    use crate::ir::{Address, Insn, RawAddress};

    fn assert_direct_flow_matches_lifter(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        let language = X86_64::resolve_default_variant()?;
        let arch = X86_64::new(language);
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
    fn test_byte_patterns_are_classified() {
        let language = X86_64::resolve_default_variant().expect("x86-64 language");
        let arch = X86_64::new(language);
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

    #[test]
    fn direct_relative_flows_match_lifted_flow() -> Result<(), Box<dyn Error>> {
        for bytes in [
            [0xeb, 0x10].as_slice(),
            &[0xeb, 0xf0],
            &[0xe9, 0x01, 0x00, 0x00, 0x00],
            &[0x75, 0x10],
            &[0x0f, 0x85, 0x01, 0x00, 0x00, 0x00],
            &[0xe8, 0x01, 0x00, 0x00, 0x00],
            &[0xe3, 0x12],
            &[0x67, 0xe3, 0x12],
            &[0xe0, 0x12],
            &[0xe1, 0x12],
            &[0xe2, 0x12],
        ] {
            assert_direct_flow_matches_lifter(bytes)?;
        }
        Ok(())
    }

    #[test]
    fn direct_indirect_flows_match_lifted_flow() -> Result<(), Box<dyn Error>> {
        for bytes in [
            [0xff, 0xe0].as_slice(),
            &[0xff, 0xd0],
            &[0xc3],
            &[0xc2, 0x08, 0x00],
        ] {
            assert_direct_flow_matches_lifter(bytes)?;
        }
        Ok(())
    }

    #[test]
    fn memory_indirect_flows_retain_lifted_resolution() -> Result<(), Box<dyn Error>> {
        let language = X86_64::resolve_default_variant()?;
        let arch = X86_64::new(language);
        let address = Address::in_default_space(0x1000u64);
        let mut context = arch.lifter();
        let mut disassembler = arch.disassembler();

        for bytes in [
            [0xff, 0x20].as_slice(),
            &[0xff, 0x10],
            &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00],
            &[0xff, 0x15, 0x10, 0x00, 0x00, 0x00],
        ] {
            let insn = disassembler.disassemble(address, bytes, context.context_mut())?;
            assert!(
                insn.needs_flow_resolution(),
                "memory-indirect flow {bytes:02x?} must retain lifted resolution",
            );
        }
        Ok(())
    }
}
