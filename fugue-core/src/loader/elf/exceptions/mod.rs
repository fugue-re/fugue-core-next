use std::collections::{BTreeMap, BTreeSet};

use object::read::elf::{ElfFile, FileHeader, ProgramHeader, SectionHeader};
use object::{Architecture, Object, ObjectSection, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::loader::elf::extensions::ExceptionContext;
use crate::loader::elf::{ElfFileRepr, ElfLoaderProperties};

mod arm;
mod eh_frame;

pub(crate) struct ElfExceptionResolver<'data, 'file, 'image, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    view: &'file ElfFileRepr<'data, 'image>,
    elf: &'file ElfFile<'data, Elf, R>,
    arch: &'file Arch,
    base: RawAddress,
    config: ElfLoaderProperties,
    function_hints: &'file mut BTreeSet<RawAddress>,
    mapping_hints: &'file mut BTreeMap<RawAddress, ContextHint>,
}

impl<'data, 'file, 'image, Elf, R> ElfExceptionResolver<'data, 'file, 'image, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        view: &'file ElfFileRepr<'data, 'image>,
        elf: &'file ElfFile<'data, Elf, R>,
        arch: &'file Arch,
        base: RawAddress,
        config: ElfLoaderProperties,
        function_hints: &'file mut BTreeSet<RawAddress>,
        mapping_hints: &'file mut BTreeMap<RawAddress, ContextHint>,
    ) -> Self {
        Self {
            view,
            elf,
            arch,
            base,
            config,
            function_hints,
            mapping_hints,
        }
    }

    fn rebase(&self, address: u64) -> RawAddress {
        self.base + address
    }

    fn section(&self, sh_type: u32) -> Option<(u64, &'data [u8])> {
        let endian = self.elf.endian();
        let section = self
            .elf
            .elf_section_table()
            .iter()
            .find(|section| section.sh_type(endian) == sh_type)?;
        let data = section.data(endian, self.elf.data()).ok()?;
        Some((section.sh_addr(endian).into(), data))
    }

    fn named_section(&self, name: &str) -> Option<(u64, &'data [u8])> {
        let section = self.elf.section_by_name(name)?;
        let data = section.data().ok()?;
        Some((section.address(), data))
    }

    fn segment(&self, p_type: u32) -> Option<(u64, &'data [u8])> {
        let endian = self.elf.endian();
        let segment = self
            .elf
            .elf_program_headers()
            .iter()
            .find(|segment| segment.p_type(endian) == p_type)?;
        let data = segment.data(endian, self.elf.data()).ok()?;
        Some((segment.p_vaddr(endian).into(), data))
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

        if self.config.is_object() {
            tracing::trace!("no exception table support for relocatable ELF objects");
            return Ok(());
        }

        let result = self
            .apply_eh_frame()
            .and_then(|()| match self.elf.architecture() {
                Architecture::Arm => self.apply_arm_exidx(),
                _ => Ok(()),
            });

        if let Err(error) = result {
            if !self.config.is_permissive() {
                return Err(error);
            }
            tracing::warn!(
                "unable to fully read ELF exception tables ({error}); keeping partial function hints"
            );
        }

        Ok(())
    }

    fn insert_function_hint(&mut self, address: u64) {
        let address = self.rebase(address);
        let address = match self.arch.canonicalise_address(address) {
            Some((canonical, context)) if canonical != address => {
                self.mapping_hints
                    .insert(canonical, ContextHint::code().with_context(context));
                canonical
            }
            _ => address,
        };
        self.function_hints.insert(address);
    }
}
