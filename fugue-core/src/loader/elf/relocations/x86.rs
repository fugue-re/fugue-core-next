use object::elf::{R_386_32, R_386_32PLT, R_386_GLOB_DAT, R_386_JMP_SLOT, R_386_RELATIVE};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationKind};

use super::{ElfSegmentRelocator, elf_relocation_type};
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_relocation(
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

        let Some(reloc_type) = elf_relocation_type(reloc) else {
            return;
        };

        match reloc_type {
            R_386_RELATIVE => {
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_386_GLOB_DAT | R_386_JMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                if reloc_type == R_386_JMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_386_32 | R_386_32PLT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let value = value.wrapping_add_signed(reloc.addend());

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
