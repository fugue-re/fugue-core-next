use object::LittleEndian as LE;
use object::ReadRef;
use object::pe::ImageRuntimeFunctionEntry;
use object::read::pe::ImageNtHeaders;

use super::PeExceptionResolver;
use crate::loader::LoaderError;
use crate::loader::pe::read::exception::{self, UNW_FLAG_CHAININFO};

impl<'data, 'file, Pe, R> PeExceptionResolver<'data, 'file, '_, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_64_runtime_functions(&mut self) -> Result<(), LoaderError> {
        for entry in exception::runtime_functions::<_, _, ImageRuntimeFunctionEntry>(self.pe)? {
            let unwind_info = entry.unwind_info_address_or_data.get(LE);
            if exception::unwind_info_flags(self.pe, unwind_info)
                .is_some_and(|flags| flags & UNW_FLAG_CHAININFO != 0)
            {
                continue;
            }

            self.function_hints
                .extend(self.rebase(entry.begin_address.get(LE)));
        }
        Ok(())
    }
}
