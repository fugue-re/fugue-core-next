use object::elf::{
    R_MIPS_32, R_MIPS_64, R_MIPS_GLOB_DAT, R_MIPS_JUMP_SLOT, R_MIPS_NONE, R_MIPS_REL32,
};
use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationTarget};

use super::ElfSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_mips64_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        let Some(composite) = self.elf_relocation_type(reloc) else {
            return;
        };

        // n64 packs three relocation types into r_info as ssym|type3|type2|type; they apply in
        // sequence, so the first step computes the value and the last non-empty step fixes the
        // width of the store.
        let steps = [
            composite & 0xff,
            (composite >> 8) & 0xff,
            (composite >> 16) & 0xff,
        ];

        let Some(size) = steps
            .iter()
            .rev()
            .find(|step| **step != R_MIPS_NONE)
            .and_then(|step| Self::mips64_relocation_size(*step))
        else {
            tracing::warn!("unsupported relocation type {reloc:?}");
            return;
        };

        let implicit = if size == 8 {
            self.mips_implicit_addend::<u64>(bytes, offset, reloc) as i64
        } else {
            self.mips_implicit_addend::<u32>(bytes, offset, reloc) as i64
        };
        let addend = reloc.addend().wrapping_add(implicit);

        let Some(value) =
            self.mips64_relocation_value(steps[0], offset, reloc, addend, is_dynamic, bytes)
        else {
            return;
        };

        tracing::trace!("applying relocation {composite:#x} at {offset:#x}: {value:#x}");

        if size == 8 {
            bytes.write_value(offset, value);
            return;
        }

        if value > u32::MAX as u64 {
            tracing::warn!("relocation {composite:#x} at {offset:#x} overflow");
            return;
        }

        bytes.write_value(offset, value as u32);
    }

    fn mips64_relocation_size(step: u32) -> Option<usize> {
        match step {
            R_MIPS_32 | R_MIPS_REL32 => Some(4),
            R_MIPS_64 | R_MIPS_GLOB_DAT | R_MIPS_JUMP_SLOT => Some(8),
            _ => None,
        }
    }

    fn mips64_relocation_value(
        &self,
        step: u32,
        offset: u64,
        reloc: &Relocation,
        addend: i64,
        is_dynamic: bool,
        bytes: &mut ImageSegmentContents<'data>,
    ) -> Option<u64> {
        match step {
            R_MIPS_32 | R_MIPS_64 | R_MIPS_REL32 => {
                // S + A when bound to a symbol, B + A when unbound (STN_UNDEF).
                match reloc.target() {
                    RelocationTarget::Symbol(_) => {
                        match self.resolve_relocation_symbol(reloc, is_dynamic) {
                            Some(symbol) => Some(symbol.wrapping_add_signed(addend)),
                            None => {
                                tracing::warn!(
                                    "failed to resolve relocation {step:#x} at {offset:#x}"
                                );
                                None
                            }
                        }
                    }
                    _ => Some(self.base.offset().wrapping_add_signed(addend)),
                }
            }
            R_MIPS_GLOB_DAT | R_MIPS_JUMP_SLOT => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {step:#x} at {offset:#x}");
                    return None;
                };

                if step == R_MIPS_JUMP_SLOT {
                    self.mark_function_symbol(value, bytes);
                } else {
                    self.mark_data_symbol(reloc, is_dynamic, bytes);
                }

                Some(value)
            }
            _ => {
                tracing::warn!("unsupported relocation type {reloc:?}");
                None
            }
        }
    }
}
