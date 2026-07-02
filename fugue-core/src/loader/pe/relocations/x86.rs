use object::ReadRef;
use object::read::pe::ImageNtHeaders;

use super::PeSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Pe, R> PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc_type: u16,
    ) {
        self.apply_generic_relocation(bytes, offset, reloc_type);
    }
}
