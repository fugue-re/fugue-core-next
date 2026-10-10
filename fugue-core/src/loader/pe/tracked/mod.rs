use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Object, ReadRef};

use crate::arch::Arch;
use crate::ir::{RawAddress, RawAddressMap};
use crate::lifter::TrackedSet;
use crate::loader::LoaderError;
use crate::loader::pe::PeFileRepr;
use crate::loader::pe::extensions::TrackedSetContext;

pub(crate) struct PeTrackedSetResolver<'data, 'file, 'image, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    view: &'file PeFileRepr<'data, 'image>,
    pe: &'file PeFile<'data, Pe, R>,
    arch: &'file Arch,
    base: RawAddress,
    tracked_sets: &'file mut RawAddressMap<TrackedSet>,
}

impl<'data, 'file, 'image, Pe, R> PeTrackedSetResolver<'data, 'file, 'image, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        view: &'file PeFileRepr<'data, 'image>,
        pe: &'file PeFile<'data, Pe, R>,
        arch: &'file Arch,
        base: RawAddress,
        tracked_sets: &'file mut RawAddressMap<TrackedSet>,
    ) -> Self {
        Self {
            view,
            pe,
            arch,
            base,
            tracked_sets,
        }
    }

    pub(crate) fn apply(&mut self) -> Result<(), LoaderError> {
        let mut context =
            TrackedSetContext::new(self.view, self.arch, self.base, self.tracked_sets);

        if context.apply_tracked_sets()? {
            return Ok(());
        }

        tracing::trace!(
            "no built-in tracked sets for {:?} PE images",
            self.pe.architecture()
        );
        Ok(())
    }
}
