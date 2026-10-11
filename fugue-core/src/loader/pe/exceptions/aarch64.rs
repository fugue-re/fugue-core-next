use object::LittleEndian as LE;
use object::ReadRef;
use object::pe::ImageArm64RuntimeFunctionEntry;
use object::read::pe::ImageNtHeaders;

use super::PeExceptionResolver;
use crate::loader::LoaderError;
use crate::loader::pe::read::exception;

impl<'data, 'file, Pe, R> PeExceptionResolver<'data, 'file, '_, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_aarch64_runtime_functions(&mut self) -> Result<(), LoaderError> {
        for entry in exception::runtime_functions::<_, _, ImageArm64RuntimeFunctionEntry>(self.pe)?
        {
            if exception::is_packed_fragment(entry.unwind_data.get(LE)) {
                continue;
            }

            self.function_hints
                .extend(self.rebase(entry.begin_address.get(LE)));
        }
        Ok(())
    }
}
