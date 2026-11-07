use object::read::macho::{MachHeader, MachOFile};
use object::{Object, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::loader::LoaderError;
use crate::loader::macho::MachOFileRepr;
use crate::loader::macho::extensions::TrackedSetContext;
use crate::storage::segments::mapping::SegmentMappingHints;

pub(crate) struct MachOTrackedSetResolver<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    view: &'file MachOFileRepr<'data>,
    macho: &'file MachOFile<'data, Mach, R>,
    arch: &'file Arch,
    base: RawAddress,
    mapping_hints: &'file mut SegmentMappingHints,
}

impl<'data, 'file, Mach, R> MachOTrackedSetResolver<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        view: &'file MachOFileRepr<'data>,
        macho: &'file MachOFile<'data, Mach, R>,
        arch: &'file Arch,
        base: RawAddress,
        mapping_hints: &'file mut SegmentMappingHints,
    ) -> Self {
        Self {
            view,
            macho,
            arch,
            base,
            mapping_hints,
        }
    }

    pub(crate) fn apply(&mut self) -> Result<(), LoaderError> {
        let mut context =
            TrackedSetContext::new(self.view, self.arch, self.base, self.mapping_hints);

        if context.apply_tracked_sets()? {
            return Ok(());
        }

        tracing::trace!(
            "no built-in tracked sets for {:?} Mach-O images",
            self.macho.architecture()
        );
        Ok(())
    }
}
