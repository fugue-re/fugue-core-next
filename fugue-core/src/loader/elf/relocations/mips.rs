use fugue_bytes::ByteCast;
use object::elf::{
    R_MIPS_16, R_MIPS_26, R_MIPS_32, R_MIPS_CALL16, R_MIPS_COPY, R_MIPS_GLOB_DAT, R_MIPS_GOT16,
    R_MIPS_HI16, R_MIPS_JALR, R_MIPS_JUMP_SLOT, R_MIPS_LO16, R_MIPS_NONE, R_MIPS_PC16,
    R_MIPS_REL32,
};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationTarget};

use super::{ElfSegmentRelocator, elf_relocation_type};
use crate::loader::ImageSegmentContents;

pub(crate) fn mips_implicit_addend<T: ByteCast + Default>(
    bytes: &ImageSegmentContents<'_>,
    offset: u64,
    reloc: &Relocation,
) -> T {
    if reloc.has_implicit_addend() {
        bytes.read_value::<T>(offset).unwrap_or_default()
    } else {
        T::default()
    }
}

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_mips_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        let Some(reloc_type) = elf_relocation_type(reloc) else {
            return;
        };

        match reloc_type {
            R_MIPS_NONE | R_MIPS_JALR => {}
            R_MIPS_REL32 => {
                // S + A when bound to a symbol, B + A when unbound (STN_UNDEF).
                let implicit = mips_implicit_addend::<u32>(bytes, offset, reloc);
                let addend = reloc.addend().wrapping_add(implicit as i64);

                let value = match reloc.target() {
                    RelocationTarget::Symbol(_) => {
                        match self.resolve_relocation_symbol(reloc, is_dynamic) {
                            Some(s) => s.wrapping_add_signed(addend),
                            None => {
                                tracing::warn!(
                                    "failed to resolve relocation {reloc_type:#x} at {offset:#x}"
                                );
                                return;
                            }
                        }
                    }
                    _ => self.base.offset().wrapping_add_signed(addend),
                };

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_MIPS_32 => {
                let implicit = mips_implicit_addend::<u32>(bytes, offset, reloc);
                let addend = reloc.addend().wrapping_add(implicit as i64);

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value = symbol.wrapping_add_signed(addend);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_MIPS_16 => {
                let implicit = mips_implicit_addend::<u16>(bytes, offset, reloc);
                let addend = reloc.addend().wrapping_add(implicit as i16 as i64);

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value = (symbol as i64).wrapping_add(addend);

                if !(i16::MIN as i64..=i16::MAX as i64).contains(&value) {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u16);
            }
            R_MIPS_26 => {
                // Target := ((A << 2) | (P & 0xf000_0000)) + S, encoded as
                // (Target >> 2) in the low 26 bits of the instruction.
                let insn = mips_implicit_addend::<u32>(bytes, offset, reloc);
                let implicit_addend = (insn & 0x03ff_ffff) << 2;
                let addend = reloc.addend().wrapping_add(implicit_addend as i64);

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                self.mark_function_symbol(symbol, bytes);

                let pc = (bytes.address().offset().wrapping_add(offset)) as u32;
                let target =
                    (symbol.wrapping_add_signed(addend) as u32).wrapping_add(pc & 0xf000_0000);

                if (target & 0x3) != 0 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} is not word aligned");
                    return;
                }

                if (target & 0xf000_0000) != (pc & 0xf000_0000) {
                    tracing::warn!(
                        "relocation {reloc_type:#x} at {offset:#x} crosses 256MB region"
                    );
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {target:#x}");

                let imm26 = (target >> 2) & 0x03ff_ffff;
                bytes.update_value::<u32>(offset, |i| (i & !0x03ff_ffff) | imm26);
            }
            R_MIPS_PC16 => {
                // (S + A - P) >> 2, with A taken from the sign-extended 16-bit
                // immediate scaled by 4.
                let insn = mips_implicit_addend::<u32>(bytes, offset, reloc);
                let implicit_addend = ((insn & 0xffff) as i16 as i64) << 2;
                let addend = reloc.addend().wrapping_add(implicit_addend);

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let pc = bytes.address().offset().wrapping_add(offset);
                let value = (symbol as i64).wrapping_add(addend).wrapping_sub(pc as i64);

                if (value & 0x3) != 0 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} is not word aligned");
                    return;
                }

                let shifted = value >> 2;
                if !(i16::MIN as i64..=i16::MAX as i64).contains(&shifted) {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                let imm16 = (shifted as i32 as u32) & 0xffff;
                bytes.update_value::<u32>(offset, |i| (i & !0xffff) | imm16);
            }
            R_MIPS_GLOB_DAT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                self.mark_data_symbol(reloc, is_dynamic, bytes);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_MIPS_JUMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                self.mark_function_symbol(value, bytes);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_MIPS_COPY => {
                // Resolved at runtime by copying the symbol's bytes into this slot; nothing useful
                // for us to apply statically.
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            R_MIPS_HI16 | R_MIPS_LO16 | R_MIPS_GOT16 | R_MIPS_CALL16 => {
                // HI16/LO16 must be paired and GOT16/CALL16 needs the GOT base; skipping for now.
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
