use object::read::elf::FileHeader;
use object::{ReadRef, Relocation, RelocationKind};

use crate::loader::LoadableSegment;

use super::ElfSegmentRelocator;

impl<'data, 'file, 'segments, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_generic_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: u64,
        reloc: &Relocation,
        reloc_type: RelocationKind,
        is_dynamic: bool,
    ) {
        let offset = offset as usize;

        match reloc_type {
            RelocationKind::Absolute => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:?} at {offset:#x}");
                    return;
                };

                let value = value.wrapping_add_signed(reloc.addend());

                tracing::trace!("applying relocation {reloc_type:?} at {offset:#x}: {value:#x}");

                if reloc.size() == 32 {
                    lsegm.write_value(offset, value as u32);
                } else {
                    lsegm.write_value(offset, value);
                }
            }
            RelocationKind::Relative
            | RelocationKind::GotRelative
            | RelocationKind::PltRelative => {
                let Some(value) = self.resolve_relocation_symbol(reloc, is_dynamic) else {
                    tracing::warn!("failed to resolve relocation {reloc_type:?} at {offset:#x}");
                    return;
                };

                if [RelocationKind::GotRelative, RelocationKind::PltRelative].contains(&reloc_type)
                {
                    self.mark_function_symbol(value, lsegm);
                }

                let value = value
                    .wrapping_add_signed(reloc.addend())
                    .wrapping_sub(lsegm.address().offset().wrapping_add(offset as u64));

                tracing::trace!("applying relocation {reloc_type:?} at {offset:#x}: {value:#x}");

                if reloc.size() == 32 {
                    lsegm.write_value(offset, value as u32);
                } else {
                    lsegm.write_value(offset, value);
                }
            }
            _ => {
                tracing::warn!("unsupported relocation kind {reloc_type:?}");
                return;
            }
        }
    }
}
