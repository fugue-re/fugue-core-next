use object::elf::{
    R_RISCV_32, R_RISCV_64, R_RISCV_BRANCH, R_RISCV_CALL, R_RISCV_CALL_PLT, R_RISCV_COPY,
    R_RISCV_IRELATIVE, R_RISCV_JAL, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE, R_RISCV_RVC_BRANCH,
    R_RISCV_RVC_JUMP,
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
    pub(crate) fn apply_riscv64_relocation(
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
            R_RISCV_RELATIVE | R_RISCV_IRELATIVE => {
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_RISCV_JUMP_SLOT | R_RISCV_64 => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let value = symbol.wrapping_add_signed(reloc.addend());

                if reloc_type == R_RISCV_JUMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_RISCV_32 => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let value = symbol.wrapping_add_signed(reloc.addend());

                self.mark_data_symbol(reloc, is_dynamic, bytes);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_RISCV_BRANCH => {
                self.apply_riscv_branch_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_RISCV_JAL => {
                self.apply_riscv_jal_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_RISCV_CALL | R_RISCV_CALL_PLT => {
                self.apply_riscv_call_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_RISCV_RVC_BRANCH => {
                self.apply_riscv_rvc_branch_relocation(
                    bytes, offset, reloc, reloc_type, is_dynamic,
                );
            }
            R_RISCV_RVC_JUMP => {
                self.apply_riscv_rvc_jump_relocation(bytes, offset, reloc, reloc_type, is_dynamic);
            }
            R_RISCV_COPY => {
                tracing::debug!("unsupported relocation type {reloc:?}");
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
