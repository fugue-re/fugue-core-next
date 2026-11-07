use object::read::elf::{ElfFile, FileHeader, ProgramHeader, SectionHeader};
use object::{Architecture, Object, ObjectKind, ObjectSection, ReadRef};

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::loader::elf::ElfFileRepr;
use crate::loader::elf::extensions::ExceptionContext;
use crate::storage::segments::mapping::SegmentMappingHints;

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
    mapping_hints: &'file mut SegmentMappingHints,
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
        mapping_hints: &'file mut SegmentMappingHints,
    ) -> Self {
        Self {
            view,
            elf,
            arch,
            base,
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
        let mut context =
            ExceptionContext::new(self.view, self.arch, self.base, self.mapping_hints);

        if context.apply_exceptions()? {
            return Ok(());
        }

        if self.elf.kind() == ObjectKind::Relocatable {
            tracing::trace!("no exception table support for relocatable ELF objects");
            return Ok(());
        }

        if let Err(error) = self.apply_eh_frame() {
            tracing::warn!(
                "unable to fully read ELF exception frames ({error}); keeping partial function hints"
            );
        }

        if self.elf.architecture() == Architecture::Arm
            && let Err(error) = self.apply_arm_exidx()
        {
            tracing::warn!(
                "unable to fully read ARM exception index ({error}); keeping partial function hints"
            );
        }

        Ok(())
    }

    fn insert_function_hint(&mut self, address: u64) {
        let address = self.rebase(address);
        let address = match self.arch.canonicalise_address(address) {
            Some((canonical, context)) if canonical != address => {
                self.mapping_hints
                    .insert_context_hint(canonical, ContextHint::code().with_context(context));
                canonical
            }
            _ => address,
        };
        self.mapping_hints.insert_function(address);
    }
}
