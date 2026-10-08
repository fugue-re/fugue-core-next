use object::elf::{R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_REL32, R_ARM_RELATIVE};
use object::read::elf::FileHeader;
use object::{ObjectSymbol, ReadRef, Relocation, RelocationKind, SymbolKind};

use super::{ElfSegmentRelocator, elf_relocation_type};
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_arm_relocation(
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
            R_ARM_RELATIVE => {
                let implicit = if reloc.has_implicit_addend() {
                    bytes.read_value::<u32>(offset).unwrap_or_default()
                } else {
                    0
                };
                let addend = reloc.addend().wrapping_add(i64::from(implicit));
                let value = self.base.offset().wrapping_add_signed(addend);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_ARM_ABS32 => {
                let implicit = if reloc.has_implicit_addend() {
                    bytes.read_value::<u32>(offset).unwrap_or_default()
                } else {
                    0
                };
                let addend = reloc.addend().wrapping_add(i64::from(implicit));

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value =
                    symbol.wrapping_add_signed(addend) | self.arm_thumb_bit(reloc, is_dynamic);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };
                let value = symbol | self.arm_thumb_bit(reloc, is_dynamic);

                if value > u32::MAX as u64 {
                    tracing::warn!("relocation {reloc_type:#x} at {offset:#x} overflow");
                    return;
                }

                if reloc_type == R_ARM_JUMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            R_ARM_REL32 => {
                let target = bytes.address().offset().wrapping_add(offset);

                let Some(symbol) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                let value = (symbol.wrapping_add_signed(reloc.addend())
                    | self.arm_thumb_bit(reloc, is_dynamic))
                .wrapping_sub(target);

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: {value:#x}");

                bytes.write_value(offset, value as u32);
            }
            _ if reloc.kind() != RelocationKind::Unknown => {
                self.apply_generic_relocation(bytes, offset, reloc, reloc.kind(), is_dynamic);
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
            }
        }
    }

    fn arm_thumb_bit(&self, reloc: &Relocation, is_dynamic: bool) -> u64 {
        let is_thumb_function = self
            .resolve_relocation_target(reloc, is_dynamic)
            .is_some_and(|symbol| symbol.kind() == SymbolKind::Text && symbol.address() & 1 == 1);
        u64::from(is_thumb_function)
    }
}
