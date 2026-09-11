use object::elf::{
    R_RISCV_32, R_RISCV_BRANCH, R_RISCV_CALL, R_RISCV_CALL_PLT, R_RISCV_COPY, R_RISCV_IRELATIVE,
    R_RISCV_JAL, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE, R_RISCV_RVC_BRANCH, R_RISCV_RVC_JUMP,
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
    pub(crate) fn riscv_displacement(
        &self,
        bytes: &ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) -> Option<i64> {
        let target = bytes.address().offset().wrapping_add(offset);

        let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
            tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
            return None;
        };

        Some(
            (symbol as i64)
                .wrapping_add(reloc.addend())
                .wrapping_sub(target as i64),
        )
    }

    pub(crate) fn mark_riscv_call_target(
        &self,
        reloc: &Relocation,
        is_dynamic: bool,
        bytes: &mut ImageSegmentContents<'data>,
    ) {
        if let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) {
            self.mark_function_symbol(symbol, bytes);
        }
    }

    pub(crate) fn apply_riscv_branch_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let Some(value) = self.riscv_displacement(bytes, offset, reloc, reloc_type, is_dynamic)
        else {
            return;
        };

        if (value & 0x1) != 0 || !(-(1i64 << 12)..(1i64 << 12)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} out of range");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // B-type scatters the 13-bit displacement as imm[12|10:5] in 31..25 and
        // imm[4:1|11] in 11..7.
        let value = value as u32;
        let encoded = ((value >> 12) & 0x1) << 31
            | ((value >> 5) & 0x3f) << 25
            | ((value >> 1) & 0xf) << 8
            | ((value >> 11) & 0x1) << 7;
        bytes.update_value::<u32>(offset, |insn| (insn & !0xfe00_0f80) | encoded);
    }

    pub(crate) fn apply_riscv_jal_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let Some(value) = self.riscv_displacement(bytes, offset, reloc, reloc_type, is_dynamic)
        else {
            return;
        };

        self.mark_riscv_call_target(reloc, is_dynamic, bytes);

        if (value & 0x1) != 0 || !(-(1i64 << 20)..(1i64 << 20)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} out of range");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // J-type scatters the 21-bit displacement as imm[20|10:1|11|19:12] in 31..12.
        let value = value as u32;
        let encoded = ((value >> 20) & 0x1) << 31
            | ((value >> 1) & 0x3ff) << 21
            | ((value >> 11) & 0x1) << 20
            | ((value >> 12) & 0xff) << 12;
        bytes.update_value::<u32>(offset, |insn| (insn & !0xffff_f000) | encoded);
    }

    pub(crate) fn apply_riscv_call_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let Some(value) = self.riscv_displacement(bytes, offset, reloc, reloc_type, is_dynamic)
        else {
            return;
        };

        self.mark_riscv_call_target(reloc, is_dynamic, bytes);

        if !(-(1i64 << 31)..(1i64 << 31)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} out of range");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // The pair is AUIPC then JALR; the high half carries the sign correction for the
        // sign-extended low half.
        let value = value as u32;
        let high = value.wrapping_add(0x800) & 0xffff_f000;
        let low = (value & 0xfff) << 20;

        bytes.update_value::<u32>(offset, |insn| (insn & !0xffff_f000) | high);
        bytes.update_value::<u32>(offset + 4, |insn| (insn & !0xfff0_0000) | low);
    }

    pub(crate) fn apply_riscv_rvc_branch_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let Some(value) = self.riscv_displacement(bytes, offset, reloc, reloc_type, is_dynamic)
        else {
            return;
        };

        if (value & 0x1) != 0 || !(-(1i64 << 8)..(1i64 << 8)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} out of range");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // CB-type scatters the 9-bit displacement as imm[8|4:3] in 12..10 and
        // imm[7:6|2:1|5] in 6..2.
        let value = value as u16;
        let encoded = ((value >> 8) & 0x1) << 12
            | ((value >> 3) & 0x3) << 10
            | ((value >> 6) & 0x3) << 5
            | ((value >> 1) & 0x3) << 3
            | ((value >> 5) & 0x1) << 2;
        bytes.update_value::<u16>(offset, |insn| (insn & !0x1c7c) | encoded);
    }

    pub(crate) fn apply_riscv_rvc_jump_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: u32,
        is_dynamic: bool,
    ) {
        let Some(value) = self.riscv_displacement(bytes, offset, reloc, reloc_type, is_dynamic)
        else {
            return;
        };

        if (value & 0x1) != 0 || !(-(1i64 << 11)..(1i64 << 11)).contains(&value) {
            tracing::warn!("relocation {reloc_type:#x} at {offset:#x} out of range");
            return;
        }

        tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

        // CJ-type scatters the 12-bit displacement as imm[11|4|9:8|10|6|7|3:1|5] in 12..2.
        let value = value as u16;
        let encoded = ((value >> 11) & 0x1) << 12
            | ((value >> 4) & 0x1) << 11
            | ((value >> 8) & 0x3) << 9
            | ((value >> 10) & 0x1) << 8
            | ((value >> 6) & 0x1) << 7
            | ((value >> 7) & 0x1) << 6
            | ((value >> 1) & 0x7) << 3
            | ((value >> 5) & 0x1) << 2;
        bytes.update_value::<u16>(offset, |insn| (insn & !0x1ffc) | encoded);
    }

    pub(crate) fn apply_riscv_relocation(
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
            R_RISCV_RELATIVE | R_RISCV_IRELATIVE => {
                let Ok(value) =
                    u32::try_from(self.base.offset().wrapping_add_signed(reloc.addend()))
                else {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value);
            }
            R_RISCV_JUMP_SLOT | R_RISCV_32 => {
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

                let Ok(relocated) = u32::try_from(value) else {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, relocated);
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
