use fallible_iterator::FallibleIterator;
use gimli::{BaseAddresses, RunTimeEndian};
use object::elf::PT_GNU_EH_FRAME;
use object::read::elf::FileHeader;
use object::{Object, ReadRef};

use super::ElfExceptionResolver;
use crate::loader::LoaderError;
use crate::loader::elf::read::exception::{self, EhFrameHdrSection, EhFrameSection};

impl<'data, 'file, Elf, R> ElfExceptionResolver<'data, 'file, '_, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_eh_frame(&mut self) -> Result<(), LoaderError> {
        let endian = if self.elf.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let address_size = if self.elf.is_64() { 8 } else { 4 };

        if let Some((address, data)) = self.segment(PT_GNU_EH_FRAME) {
            let bases = BaseAddresses::default().set_eh_frame_hdr(address);
            let header = EhFrameHdrSection::new(data, endian)
                .parse(&bases, address_size)
                .map_err(LoaderError::format)?;
            if let Some(table) = header.table() {
                let mut functions = exception::eh_frame_hdr_functions(&table, &bases);
                while let Some(function) = functions.next()? {
                    if function != 0 {
                        self.insert_function_hint(function);
                    }
                }
                return Ok(());
            }
        }

        let Some((address, data)) = self.named_section(".eh_frame") else {
            return Ok(());
        };
        let bases = BaseAddresses::default().set_eh_frame(address);
        let mut eh_frame = EhFrameSection::new(data, endian);
        eh_frame.set_address_size(address_size);

        let mut functions = exception::eh_frame_functions(&eh_frame, &bases);
        while let Some(function) = functions.next()? {
            if function != 0 {
                self.insert_function_hint(function);
            }
        }

        Ok(())
    }
}
