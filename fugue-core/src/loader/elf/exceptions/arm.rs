use std::mem;

use object::ReadRef;
use object::elf::{PT_ARM_EXIDX, SHT_ARM_EXIDX};
use object::read::elf::FileHeader;

use super::ElfExceptionResolver;
use crate::loader::LoaderError;
use crate::loader::elf::read::exception::ExidxEntry;

impl<'data, 'file, Elf, R> ElfExceptionResolver<'data, 'file, '_, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_arm_exidx(&mut self) -> Result<(), LoaderError> {
        let Some((address, data)) = self
            .section(SHT_ARM_EXIDX)
            .or_else(|| self.segment(PT_ARM_EXIDX))
        else {
            return Ok(());
        };

        let endian = self.elf.endian();
        let mut place = address as u32;
        for entry in ExidxEntry::<Elf::Endian>::parse_table(data)? {
            self.insert_function_hint(entry.function_address(endian, place).into());
            place = place.wrapping_add(mem::size_of::<ExidxEntry<Elf::Endian>>() as u32);
        }

        Ok(())
    }
}
