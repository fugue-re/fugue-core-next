use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Object, ReadRef};

use crate::ir::RawAddressMap;
use crate::lifter::TrackedSet;

pub(crate) struct PeTrackedSetResolver<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pe: &'file PeFile<'data, Pe, R>,
}

impl<'data, 'file, Pe, R> PeTrackedSetResolver<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(pe: &'file PeFile<'data, Pe, R>) -> Self {
        Self { pe }
    }

    pub(crate) fn apply(&self, _: &mut RawAddressMap<TrackedSet>) {
        tracing::trace!(
            "no built-in tracked sets for {:?} PE images",
            self.pe.architecture()
        );
    }
}
