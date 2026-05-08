use object::elf::{
    R_AARCH64_CALL26, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_JUMP26,
    R_AARCH64_P32_GLOB_DAT, R_AARCH64_P32_JUMP_SLOT, R_AARCH64_P32_RELATIVE, R_AARCH64_RELATIVE,
};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationEncoding, RelocationKind};

use super::ElfSegmentRelocator;
use crate::loader::LoadableSegment;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn apply_aarch64_call_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: usize,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let target = lsegm.address().offset().wrapping_add(offset as u64);

        let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
            tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
            return;
        };

        self.mark_function_symbol(value, lsegm);

        let value = i128::from(value) + i128::from(reloc.addend()) - i128::from(target);

        if (value & 0x3) != 0 {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} is not word aligned");
            return;
        }

        let shifted = value >> 2;
        if !((-(1i128 << 25))..(1i128 << 25)).contains(&shifted) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        let imm26 = (shifted as i64 as u32) & 0x03ff_ffff;
        lsegm.update_value::<u32>(offset, |insn| (insn & !0x03ff_ffff) | imm26);
    }

    pub(crate) fn apply_aarch64_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        match (reloc.kind(), reloc.encoding()) {
            (RelocationKind::PltRelative, RelocationEncoding::AArch64Call) => {
                self.apply_aarch64_call_relocation(
                    lsegm,
                    offset as usize,
                    reloc,
                    R_AARCH64_CALL26,
                    is_dynamic,
                );
                return;
            }
            (kind, _) if kind != RelocationKind::Unknown => {
                self.apply_generic_relocation(lsegm, offset, reloc, kind, is_dynamic);
                return;
            }
            _ => {}
        }

        let Some(reloc_type) = self.elf_relocation_type(reloc) else {
            return;
        };

        match reloc_type {
            R_AARCH64_RELATIVE => {
                let offset = offset as usize;
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                lsegm.write_value(offset, value);
            }
            R_AARCH64_P32_RELATIVE => {
                let offset = offset as usize;
                let value = self.base.offset().wrapping_add_signed(reloc.addend());

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                lsegm.write_value(offset, value as u32);
            }
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let offset = offset as usize;

                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if reloc_type == R_AARCH64_JUMP_SLOT {
                    self.mark_function_symbol(value, lsegm);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                lsegm.write_value(offset, value);
            }
            R_AARCH64_CALL26 | R_AARCH64_JUMP26 => {
                self.apply_aarch64_call_relocation(
                    lsegm,
                    offset as usize,
                    reloc,
                    reloc_type,
                    is_dynamic,
                );
            }
            R_AARCH64_P32_GLOB_DAT | R_AARCH64_P32_JUMP_SLOT => {
                let offset = offset as usize;

                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                if reloc_type == R_AARCH64_P32_JUMP_SLOT {
                    self.mark_function_symbol(value, lsegm);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                lsegm.write_value(offset, value as u32);
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }
}
