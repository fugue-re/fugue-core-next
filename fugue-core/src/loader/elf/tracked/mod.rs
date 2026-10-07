use object::read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader, SectionHeader};
use object::{Architecture, Object, ReadRef};

use crate::arch::Arch;
use crate::ir::{RawAddress, RawAddressMap};
use crate::lifter::TrackedSet;

mod mips;
mod mips64;
mod x86;

pub(crate) struct ElfTrackedSetResolver<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    elf: &'file ElfFile<'data, Elf, R>,
    arch: &'file Arch,
    base: RawAddress,
}

impl<'data, 'file, Elf, R> ElfTrackedSetResolver<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        arch: &'file Arch,
        base: RawAddress,
    ) -> Self {
        Self { elf, arch, base }
    }

    pub(crate) fn apply(&self, tracked_sets: &mut RawAddressMap<TrackedSet>) {
        match self.elf.architecture() {
            Architecture::I386 => self.apply_x86_tracked_sets(tracked_sets),
            Architecture::Mips => self.apply_mips_tracked_sets(tracked_sets),
            Architecture::Mips64 => self.apply_mips64_tracked_sets(tracked_sets),
            _ => (),
        }
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
