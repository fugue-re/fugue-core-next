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
        let functions = {
            let mut place = address as u32;
            let mut contexts = self.mapping_hints.context_hints_in_range(..).peekable();
            let mut has_context = false;
            let mut functions = Vec::new();
            for entry in ExidxEntry::<Elf::Endian>::parse_table(data)? {
                let function = entry.function_address(endian, place).into();
                let rebased = self.base + function;
                while let Some((_, hint)) = contexts.next_if(|(address, _)| *address <= rebased) {
                    has_context = hint.context().is_some();
                }
                if has_context {
                    functions.push(function);
                }
                place = place.wrapping_add(mem::size_of::<ExidxEntry<Elf::Endian>>() as u32);
            }
            functions
        };

        for function in functions {
            self.insert_function_hint(function);
        }

        Ok(())
    }
}
