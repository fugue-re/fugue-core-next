use object::elf::{
    R_PPC_ADDR16_HA, R_PPC_ADDR16_HI, R_PPC_ADDR16_LO, R_PPC_COPY, R_PPC_GLOB_DAT, R_PPC_JMP_SLOT,
    R_PPC_REL24, R_PPC_REL32, R_PPC_RELATIVE, R_PPC64_ADDR16_HA, R_PPC64_ADDR16_HI,
    R_PPC64_ADDR16_LO, R_PPC64_COPY, R_PPC64_GLOB_DAT, R_PPC64_JMP_SLOT, R_PPC64_REL24,
    R_PPC64_REL32, R_PPC64_REL64, R_PPC64_RELATIVE, R_PPC64_TOC, R_PPC64_TOC16, R_PPC64_TOC16_HA,
    R_PPC64_TOC16_HI, R_PPC64_TOC16_LO,
};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationKind};

use super::ElfSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn apply_ppc_branch_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let target = bytes.address().offset().wrapping_add(offset);

        let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
            tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
            return;
        };

        self.mark_function_symbol(value, bytes);

        let value = i128::from(value) + i128::from(reloc.addend()) - i128::from(target);

        if (value & 0x3) != 0 {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} is not word aligned");
            return;
        }

        if !((-(1i128 << 25))..(1i128 << 25)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // LI occupies bits 2..26 of the I-form instruction; AA and LK are preserved.
        let displacement = (value as i64 as u32) & 0x03ff_fffc;
        bytes.update_value::<u32>(offset, |insn| (insn & !0x03ff_fffc) | displacement);
    }

    fn apply_ppc_half16_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        half: Half16,
        is_dynamic: bool,
    ) {
        let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
            tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
            return;
        };

        let value = symbol.wrapping_add_signed(reloc.addend());

        if value > u32::MAX as u64 {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // #ha compensates for the sign of the paired #lo half by carrying 0x8000.
        let half = match half {
            Half16::Lo => value as u16,
            Half16::Hi => (value >> 16) as u16,
            Half16::Ha => (value.wrapping_add(0x8000) >> 16) as u16,
        };

        bytes.write_value(offset, half);
    }

    pub(crate) fn apply_ppc_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        if reloc.kind() != RelocationKind::Unknown {
            self.apply_generic_relocation(bytes, offset, reloc, reloc.kind(), is_dynamic);
            return;
        }

        let Some(reloc_type) = self.elf_relocation_type(reloc) else {
            return;
        };

        match reloc_type {
            R_PPC_RELATIVE => {
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_PPC_GLOB_DAT | R_PPC_JMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                if reloc_type == R_PPC_JMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_PPC_REL24 => {
                self.apply_ppc_branch_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_PPC_REL32 => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let target = bytes.address().offset().wrapping_add(offset);
                let value = symbol
                    .wrapping_add_signed(reloc.addend())
                    .wrapping_sub(target);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_PPC_ADDR16_LO => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Lo,
                    is_dynamic,
                );
            }
            R_PPC_ADDR16_HI => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Hi,
                    is_dynamic,
                );
            }
            R_PPC_ADDR16_HA => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Ha,
                    is_dynamic,
                );
            }
            R_PPC_COPY => {
                // Resolved at runtime by copying the symbol's bytes into this slot; nothing useful
                // for us to apply statically.
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }

    pub(crate) fn apply_ppc64_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        if reloc.kind() != RelocationKind::Unknown {
            self.apply_generic_relocation(bytes, offset, reloc, reloc.kind(), is_dynamic);
            return;
        }

        let Some(reloc_type) = self.elf_relocation_type(reloc) else {
            return;
        };

        match reloc_type {
            R_PPC64_RELATIVE => {
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_PPC64_GLOB_DAT | R_PPC64_JMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if reloc_type == R_PPC64_JMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_PPC64_REL24 => {
                self.apply_ppc_branch_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_PPC64_REL32 => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let target = bytes.address().offset().wrapping_add(offset);
                let value = symbol
                    .wrapping_add_signed(reloc.addend())
                    .wrapping_sub(target);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_PPC64_REL64 => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let target = bytes.address().offset().wrapping_add(offset);
                let value = symbol
                    .wrapping_add_signed(reloc.addend())
                    .wrapping_sub(target);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_PPC64_ADDR16_LO => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Lo,
                    is_dynamic,
                );
            }
            R_PPC64_ADDR16_HI => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Hi,
                    is_dynamic,
                );
            }
            R_PPC64_ADDR16_HA => {
                self.apply_ppc_half16_relocation(
                    bytes,
                    offset,
                    reloc,
                    reloc_type,
                    Half16::Ha,
                    is_dynamic,
                );
            }
            R_PPC64_COPY => {
                // Resolved at runtime by copying the symbol's bytes into this slot; nothing useful
                // for us to apply statically.
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            R_PPC64_TOC | R_PPC64_TOC16 | R_PPC64_TOC16_LO | R_PPC64_TOC16_HI
            | R_PPC64_TOC16_HA => {
                // Relative to the object's TOC base, which the loader does not track.
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Half16 {
    Ha,
    Hi,
    Lo,
}
