use object::read::macho::{MachHeader, MachOFile};
use object::{Object, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::loader::LoaderError;
use crate::loader::macho::MachOFileRepr;
use crate::loader::macho::extensions::ExceptionContext;
use crate::storage::segments::mapping::SegmentMappingHints;

pub(crate) struct MachOExceptionResolver<'data, 'file, Mach, R>
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

impl<'data, 'file, Mach, R> MachOExceptionResolver<'data, 'file, Mach, R>
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
            ExceptionContext::new(self.view, self.arch, self.base, self.mapping_hints);

        if context.apply_exceptions()? {
            return Ok(());
        }

        tracing::trace!(
            "no built-in exception support for {:?} Mach-O images",
            self.macho.architecture()
        );
        Ok(())
    }
}
