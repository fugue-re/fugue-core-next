use object::elf::{
    R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_GOT64, R_X86_64_GOTPCREL,
    R_X86_64_GOTPCRELX, R_X86_64_JUMP_SLOT, R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_RELATIVE,
    R_X86_64_RELATIVE64, R_X86_64_REX_GOTPCRELX,
};
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
    pub(crate) fn apply_x86_64_relocation(
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
            R_X86_64_RELATIVE | R_X86_64_RELATIVE64 => {
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}",);

                bytes.write_value(offset, value);
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if reloc_type == R_X86_64_JUMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_X86_64_64 | R_X86_64_GOT64 => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if reloc_type == R_X86_64_GOT64 {
                    self.mark_function_symbol(value, bytes);
                }

                let value = value.wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_X86_64_32 => {
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
            R_X86_64_32S => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let value = value.wrapping_add_signed(reloc.addend());

                if value > i32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as i32);
            }
            R_X86_64_PLT32
            | R_X86_64_PC32
            | R_X86_64_GOTPCREL
            | R_X86_64_GOTPCRELX
            | R_X86_64_REX_GOTPCRELX => {
                let target = bytes.address().offset().wrapping_add(offset);

                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                self.mark_function_symbol(value, bytes);

                let value =
                    (value.wrapping_add_signed(reloc.addend()) as u32).wrapping_sub(target as u32);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
