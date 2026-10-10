use object::read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader, SectionHeader};
use object::{Architecture, Object, ReadRef};

use crate::arch::Arch;
use crate::ir::{RawAddress, RawAddressMap};
use crate::lifter::TrackedSet;
use crate::loader::LoaderError;
use crate::loader::elf::ElfFileRepr;
use crate::loader::elf::extensions::TrackedSetContext;

mod mips;
mod mips64;
mod x86;

pub(crate) struct ElfTrackedSetResolver<'data, 'file, 'image, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    view: &'file ElfFileRepr<'data, 'image>,
    elf: &'file ElfFile<'data, Elf, R>,
    arch: &'file Arch,
    base: RawAddress,
    tracked_sets: &'file mut RawAddressMap<TrackedSet>,
}

impl<'data, 'file, 'image, Elf, R> ElfTrackedSetResolver<'data, 'file, 'image, Elf, R>
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
        tracked_sets: &'file mut RawAddressMap<TrackedSet>,
    ) -> Self {
        Self {
            view,
            elf,
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

        match self.elf.architecture() {
            Architecture::I386 => self.apply_x86_tracked_sets(),
            Architecture::Mips => self.apply_mips_tracked_sets(),
            Architecture::Mips64 => self.apply_mips64_tracked_sets(),
            _ => (),
        }
        Ok(())
    }

    fn dynamic_value(&self, tag: i64) -> Option<u64> {
        let endian = self.elf.endian();
        let data = self.elf.data();

        self.elf
            .elf_program_headers()
            .iter()
            .find_map(|phdr| phdr.dynamic(endian, data).ok().flatten())?
            .iter()
            .find(|entry| entry.tag(endian) == tag)
            .map(|entry| entry.val(endian))
    }

    fn section_data(&self, sh_type: u32) -> Option<&'data [u8]> {
        let endian = self.elf.endian();
        self.elf
            .elf_section_table()
            .iter()
            .find(|section| section.sh_type(endian) == sh_type)?
            .data(endian, self.elf.data())
            .ok()
    }

    fn rebase(&self, address: u64) -> RawAddress {
        self.base + address
    }
}
