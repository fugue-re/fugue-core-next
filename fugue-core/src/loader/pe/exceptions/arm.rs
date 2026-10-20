use object::LittleEndian as LE;
use object::ReadRef;
use object::pe::ImageArmRuntimeFunctionEntry;
use object::read::pe::ImageNtHeaders;

use super::PeExceptionResolver;
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::loader::pe::read::exception;

impl<'data, 'file, Pe, R> PeExceptionResolver<'data, 'file, '_, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_arm_runtime_functions(&mut self) -> Result<(), LoaderError> {
        for entry in exception::runtime_functions::<_, _, ImageArmRuntimeFunctionEntry>(self.pe)? {
            if exception::is_packed_fragment(entry.unwind_data.get(LE)) {
                continue;
            }

            let Some(address) = self.rebase(entry.begin_address.get(LE)) else {
                continue;
            };
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
        Ok(())
    }
}
