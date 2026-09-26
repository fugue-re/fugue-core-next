use object::read::macho::MachHeader;
use object::{ReadRef, Relocation, RelocationEncoding};

use super::MachOSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Mach, R> MachOSegmentRelocator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_aarch64_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        relocation: &Relocation,
    ) {
        if relocation.encoding() != RelocationEncoding::AArch64Call {
            self.apply_generic_relocation(bytes, offset, relocation);
            return;
        }

        let Some(instruction) = bytes.read_value::<u32>(offset) else {
            tracing::warn!("invalid AArch64 Mach-O relocation at {offset:#x}");
            return;
        };
        let Some(target) = self.resolve_relocation_value(relocation) else {
            tracing::warn!("failed to resolve AArch64 Mach-O relocation at {offset:#x}");
            return;
        };

        let encoded = if relocation.has_implicit_addend() {
            i64::from(((instruction & 0x03ff_ffff) << 6) as i32 >> 4)
        } else {
            0
        };
        let patch = bytes.address().offset().wrapping_add(offset);
        let value = target
            .wrapping_add_signed(relocation.addend())
            .wrapping_add_signed(encoded)
            .wrapping_sub(patch) as i64;
        if value & 3 != 0 {
            tracing::warn!("unaligned AArch64 Mach-O relocation at {offset:#x}");
            return;
        }

        let shifted = value >> 2;
        if !((-(1i64 << 25))..(1i64 << 25)).contains(&shifted) {
            tracing::warn!("AArch64 Mach-O relocation at {offset:#x} overflow");
            return;
        }

        let immediate = (shifted as u32) & 0x03ff_ffff;
        bytes.write_value(offset, (instruction & !0x03ff_ffff) | immediate);
        self.mark_function_symbol(target, bytes);
    }
}
