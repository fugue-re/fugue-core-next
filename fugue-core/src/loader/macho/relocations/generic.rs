use object::read::macho::MachHeader;
use object::{ReadRef, Relocation, RelocationKind};

use super::MachOSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Mach, R> MachOSegmentRelocator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_generic_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        relocation: &Relocation,
    ) {
        let Some(target) = self.resolve_relocation_target(relocation.target()) else {
            tracing::warn!("failed to resolve Mach-O relocation at {offset:#x}");
            return;
        };
        let Some(mut value) = self.resolve_relocation_value(relocation) else {
            tracing::warn!("failed to resolve Mach-O relocation at {offset:#x}");
            return;
        };
        value = value.wrapping_add_signed(relocation.addend());
        if relocation.has_implicit_addend() {
            let Some(addend) = implicit_addend(bytes, offset, relocation.size()) else {
                tracing::warn!("invalid Mach-O relocation width at {offset:#x}");
                return;
            };
            value = value.wrapping_add(addend);
        }

        match relocation.kind() {
            RelocationKind::GotRelative
            | RelocationKind::PltRelative
            | RelocationKind::Relative => {
                let patch = bytes.address().offset().wrapping_add(offset);
                value = value.wrapping_sub(patch);
                if matches!(
                    relocation.kind(),
                    RelocationKind::GotRelative | RelocationKind::PltRelative
                ) {
                    self.mark_function_symbol(target, bytes);
                }
            }
            RelocationKind::Absolute => {}
            kind => {
                tracing::warn!("unsupported Mach-O relocation kind {kind:?} at {offset:#x}");
                return;
            }
        }

        if !write_relocation(bytes, offset, relocation.size(), value) {
            tracing::warn!(
                "Mach-O relocation at {offset:#x} does not fit {} bits",
                relocation.size()
            );
        }
    }
}

fn implicit_addend(bytes: &ImageSegmentContents<'_>, offset: u64, size: u8) -> Option<u64> {
    match size {
        8 => bytes.read_value::<u8>(offset).map(u64::from),
        16 => bytes.read_value::<u16>(offset).map(u64::from),
        32 => bytes.read_value::<u32>(offset).map(u64::from),
        64 => bytes.read_value::<u64>(offset),
        _ => None,
    }
}

fn write_relocation(
    bytes: &mut ImageSegmentContents<'_>,
    offset: u64,
    size: u8,
    value: u64,
) -> bool {
    match size {
        8 => bytes.write_value(offset, value as u8).is_some(),
        16 => bytes.write_value(offset, value as u16).is_some(),
        32 => bytes.write_value(offset, value as u32).is_some(),
        64 => bytes.write_value(offset, value).is_some(),
        _ => false,
    }
}
