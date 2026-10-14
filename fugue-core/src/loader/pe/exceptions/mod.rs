use std::collections::{BTreeMap, BTreeSet};

use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Architecture, Object, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::loader::pe::extensions::ExceptionContext;
use crate::loader::pe::{PeFileRepr, PeLoaderProperties};

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
    config: PeLoaderProperties,
    function_hints: &'file mut BTreeSet<RawAddress>,
    mapping_hints: &'file mut BTreeMap<RawAddress, ContextHint>,
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
        config: PeLoaderProperties,
        function_hints: &'file mut BTreeSet<RawAddress>,
        mapping_hints: &'file mut BTreeMap<RawAddress, ContextHint>,
    ) -> Self {
        Self {
            view,
            pe,
            arch,
            base,
            config,
            function_hints,
            mapping_hints,
        }
    }

    pub(crate) fn apply(&mut self) -> Result<(), LoaderError> {
        let mut context = ExceptionContext::new(
            self.view,
            self.arch,
            self.base,
            self.function_hints,
            self.mapping_hints,
        );

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
            if !self.config.is_permissive() {
                return Err(error);
            }
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
