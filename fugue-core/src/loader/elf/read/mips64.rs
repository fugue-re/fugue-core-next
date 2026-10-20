use object::Endian;
use object::read::elf::{FileHeader, Rela};

pub fn relocation_symbol<Elf: FileHeader>(relocation: &Elf::Rela, endian: Elf::Endian) -> u32 {
    relocation.r_sym(endian, endian.is_little_endian())
}
