use object::elf::{
    R_PPC64_ADDR16_HA, R_PPC64_ADDR16_HI, R_PPC64_ADDR16_LO, R_PPC64_COPY, R_PPC64_GLOB_DAT,
    R_PPC64_JMP_SLOT, R_PPC64_REL24, R_PPC64_REL32, R_PPC64_REL64, R_PPC64_RELATIVE, R_PPC64_TOC,
    R_PPC64_TOC16, R_PPC64_TOC16_HA, R_PPC64_TOC16_HI, R_PPC64_TOC16_LO,
};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationKind};

use super::ElfSegmentRelocator;
use super::ppc::Half16;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
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
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            R_PPC64_TOC | R_PPC64_TOC16 | R_PPC64_TOC16_LO | R_PPC64_TOC16_HI
            | R_PPC64_TOC16_HA => {
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
