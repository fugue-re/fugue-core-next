use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Architecture, Object, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::loader::LoaderError;
use crate::loader::pe::PeFileRepr;
use crate::loader::pe::extensions::ExceptionContext;
use crate::storage::segments::mapping::SegmentMappingHints;

mod aarch64;
mod arm;
mod x86_64;

pub(crate) struct PeExceptionResolver<'data, 'file, 'image, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    view: &'file PeFileRepr<'data, 'image>,
    pe: &'file PeFile<'data, Pe, R>,
    arch: &'file Arch,
    base: RawAddress,
    mapping_hints: &'file mut SegmentMappingHints,
}

impl<'data, 'file, 'image, Pe, R> PeExceptionResolver<'data, 'file, 'image, Pe, R>
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
        mapping_hints: &'file mut SegmentMappingHints,
    ) -> Self {
        Self {
            view,
            pe,
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

        let result = match self.pe.architecture() {
            Architecture::Aarch64 => self.apply_aarch64_runtime_functions(),
            Architecture::Arm => self.apply_arm_runtime_functions(),
            Architecture::X86_64 => self.apply_x86_64_runtime_functions(),
            architecture => {
                tracing::trace!("no exception directory support for {architecture:?} PE images");
                Ok(())
            }
        };

        if let Err(error) = result {
            tracing::warn!(
                "unable to fully read PE exception directory ({error}); keeping partial function hints"
            );
        }

        Ok(())
    }

    fn rebase(&self, address: u32) -> Option<RawAddress> {
        if address == 0 {
            return None;
        }
        self.base.checked_add(address)
    }
}
