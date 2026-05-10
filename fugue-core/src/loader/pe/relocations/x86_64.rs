use super::PeSegmentRelocator;
use crate::loader::LoadableSegment;

impl<'data, 'file, Pe, R> PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: object::read::pe::ImageNtHeaders,
    R: object::ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_64_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: usize,
        reloc_type: u16,
    ) {
        self.apply_generic_relocation(lsegm, offset, reloc_type);
    }
}
