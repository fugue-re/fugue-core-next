use std::ops::RangeInclusive;

use fugue_bytes::ByteCast;
use object::elf::{
    DT_MIPS_GOTSYM, DT_MIPS_LOCAL_GOTNO, DT_MIPS_SYMTABNO, DT_PLTGOT, R_MIPS_16, R_MIPS_26,
    R_MIPS_32, R_MIPS_CALL16, R_MIPS_COPY, R_MIPS_GLOB_DAT, R_MIPS_GOT16, R_MIPS_HI16, R_MIPS_JALR,
    R_MIPS_JUMP_SLOT, R_MIPS_LO16, R_MIPS_NONE, R_MIPS_PC16, R_MIPS_REL32,
};
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Sym};
use object::{Object, ObjectSymbol, ReadRef, Relocation, RelocationTarget, SymbolFlags};

use super::{ElfSegmentRelocator, elf_relocation_type};
use crate::ir::SymbolIndex;
use crate::lifter::ContextHint;
use crate::loader::ImageSegmentContents;
use crate::loader::elf::ELF_DYNSYM_SELECTOR;
use crate::loader::elf::read::mips;

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
    pub(crate) fn apply_mips_global_got(
        &self,
        origin: RangeInclusive<u64>,
        bytes: &mut ImageSegmentContents<'data>,
    ) {
        let endian = self.elf.endian();
        let data = self.elf.data();

        let Some(dynamic) = self
            .elf
            .elf_program_headers()
            .iter()
            .find_map(|phdr| phdr.dynamic(endian, data).ok().flatten())
        else {
            return;
        };

        let value = |tag| {
            dynamic
                .iter()
                .find(|entry| entry.tag(endian) == tag)
                .map(|entry| entry.val(endian))
        };

        let (Some(pltgot), Some(local_gotno), Some(gotsym), Some(symtabno)) = (
            value(DT_PLTGOT),
            value(DT_MIPS_LOCAL_GOTNO),
            value(DT_MIPS_GOTSYM),
            value(DT_MIPS_SYMTABNO),
        ) else {
            tracing::trace!("no MIPS global GOT");
            return;
        };

        let entry_size = if self.elf.is_64() { 8 } else { 4 };

        for index in gotsym..symtabno {
            let Some(slot) = (index - gotsym)
                .checked_add(local_gotno)
                .and_then(|entry| entry.checked_mul(entry_size))
                .and_then(|offset| pltgot.checked_add(offset))
            else {
                tracing::warn!("MIPS global GOT entry for symbol {index} overflows");
                return;
            };

            if !origin.contains(&slot) {
                continue;
            }

            let Some((_, entry)) = self
                .symbols
                .get_by_index(SymbolIndex::new(ELF_DYNSYM_SELECTOR, index as usize))
            else {
                tracing::trace!("no dynamic symbol {index} for MIPS global GOT slot {slot:#x}");
                continue;
            };

            let is_compressed = self
                .elf
                .elf_dynamic_symbol_table()
                .symbols()
                .get(index as usize)
                .is_some_and(|symbol| mips::is_compressed(symbol.st_other()));
            let value = entry.address().raw_offset() | u64::from(is_compressed);

            if entry.is_function() {
                self.mark_function_symbol(value, bytes);
            } else if entry.is_data() {
                bytes.add_mapping_hint(value, ContextHint::data());
            }

            tracing::trace!("binding MIPS global GOT slot {slot:#x} to {value:#x}");

            let offset = slot - origin.start();

            if self.elf.is_64() {
                bytes.write_value(offset, value);
            } else if let Ok(value) = u32::try_from(value) {
                bytes.write_value(offset, value);
            } else {
                tracing::warn!("MIPS global GOT slot {slot:#x} overflow");
            }
        }
    }

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
                            Some(s) => (s | self.mips_isa_bit(reloc, is_dynamic))
                                .wrapping_add_signed(addend),
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
                let value =
                    (symbol | self.mips_isa_bit(reloc, is_dynamic)).wrapping_add_signed(addend);

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
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value = symbol | self.mips_isa_bit(reloc, is_dynamic);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                self.mark_data_symbol(reloc, is_dynamic, bytes);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_MIPS_JUMP_SLOT => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value = symbol | self.mips_isa_bit(reloc, is_dynamic);

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

    pub(crate) fn mips_isa_bit(&self, reloc: &Relocation, is_dynamic: bool) -> u64 {
        let is_compressed = self
            .resolve_relocation_target(reloc, is_dynamic)
            .is_some_and(|symbol| {
                matches!(symbol.flags(), SymbolFlags::Elf { st_other, .. } if mips::is_compressed(st_other))
            });
        u64::from(is_compressed)
    }
}
