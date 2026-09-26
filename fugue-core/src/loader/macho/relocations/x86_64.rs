use object::read::macho::MachHeader;
use object::{ReadRef, Relocation};

use super::MachOSegmentRelocator;
use crate::loader::ImageSegmentContents;

impl<'data, 'file, Mach, R> MachOSegmentRelocator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_64_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        relocation: &Relocation,
    ) {
        self.apply_generic_relocation(bytes, offset, relocation);
    }
}
