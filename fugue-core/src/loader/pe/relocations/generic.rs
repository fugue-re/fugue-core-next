use object::ReadRef;
use object::pe::{
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_LOW,
};
use object::read::pe::ImageNtHeaders;

use super::PeSegmentRelocator;
use crate::loader::ImageSegmentBytes;

impl<'data, 'file, Pe, R> PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_generic_relocation(
        &self,
        bytes: &mut ImageSegmentBytes<'data>,
        offset: usize,
        reloc_type: u16,
    ) {
        match reloc_type {
            IMAGE_REL_BASED_ABSOLUTE => {}
            IMAGE_REL_BASED_HIGH => {
                let value = self.base_delta_high();
                let Some(current) = bytes.read_value::<u16>(offset) else {
                    tracing::warn!("failed to read relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: +{value:#x}");

                bytes.write_value(offset, current.wrapping_add(value));
            }
            IMAGE_REL_BASED_LOW => {
                let value = self.base_delta_low();
                let Some(current) = bytes.read_value::<u16>(offset) else {
                    tracing::warn!("failed to read relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: +{value:#x}");

                bytes.write_value(offset, current.wrapping_add(value));
            }
            IMAGE_REL_BASED_HIGHLOW => {
                let value = self.base_delta_u32();
                let Some(current) = bytes.read_value::<u32>(offset) else {
                    tracing::warn!("failed to read relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: +{value:#x}");

                bytes.write_value(offset, current.wrapping_add(value));
            }
            IMAGE_REL_BASED_DIR64 => {
                let value = self.base_delta_u64();
                let Some(current) = bytes.read_value::<u64>(offset) else {
                    tracing::warn!("failed to read relocation {reloc_type:#x} at {offset:#x}");
                    return;
                };

                tracing::trace!("applying relocation {reloc_type:#x} at {offset:#x}: +{value:#x}");

                bytes.write_value(offset, current.wrapping_add(value));
            }
            _ => {
                tracing::warn!("unsupported PE relocation type {reloc_type:#x}");
            }
        }
    }
}
