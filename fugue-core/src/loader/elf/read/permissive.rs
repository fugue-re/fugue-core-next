use std::marker::PhantomData;

use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::FileHeader;
use object::{Endian, Endianness, FileKind, pod};
use thiserror::Error;

use crate::loader::LoaderError;
use crate::types::BytesOrMapping;

#[derive(Debug, Error)]
enum SectionHeaderRepairError {
    #[error("invalid file header")]
    InvalidFileHeader,
}

pub(crate) fn try_repair<'data>(
    data: BytesOrMapping<'data>,
) -> Result<Option<BytesOrMapping<'data>>, LoaderError> {
    match FileKind::parse(data.as_ref()).map_err(LoaderError::format)? {
        FileKind::Elf32 => {
            let Some(plan) = SectionHeaderRepairPlan::<FileHeader32<Endianness>>::try_new(&data)?
            else {
                return Ok(None);
            };
            plan.apply(data)
        }
        FileKind::Elf64 => {
            let Some(plan) = SectionHeaderRepairPlan::<FileHeader64<Endianness>>::try_new(&data)?
            else {
                return Ok(None);
            };
            plan.apply(data)
        }
        _ => {
            tracing::trace!("section header repair is not applicable");
            Ok(None)
        }
    }
}

trait SectionHeaderFields: FileHeader {
    fn clear_section_headers(&mut self, endian: Self::Endian);
}

impl<E: Endian> SectionHeaderFields for FileHeader32<E> {
    fn clear_section_headers(&mut self, endian: E) {
        self.e_shoff.set(endian, 0);
        self.e_shnum.set(endian, 0);
        self.e_shstrndx.set(endian, 0);
    }
}

impl<E: Endian> SectionHeaderFields for FileHeader64<E> {
    fn clear_section_headers(&mut self, endian: E) {
        self.e_shoff.set(endian, 0);
        self.e_shnum.set(endian, 0);
        self.e_shstrndx.set(endian, 0);
    }
}

struct SectionHeaderRepairPlan<Elf>
where
    Elf: SectionHeaderFields,
{
    endian: Elf::Endian,
    _marker: PhantomData<Elf>,
}

impl<Elf> SectionHeaderRepairPlan<Elf>
where
    Elf: SectionHeaderFields,
{
    fn try_new(data: &[u8]) -> Result<Option<Self>, LoaderError> {
        let header = Elf::parse(data).map_err(LoaderError::format)?;
        let endian = header.endian().map_err(LoaderError::format)?;
        header
            .program_headers(endian, data)
            .map_err(LoaderError::format)?;

        if header.sections(endian, data).is_ok() {
            tracing::trace!("section header repair is not applicable");
            return Ok(None);
        }

        Ok(Some(Self {
            endian,
            _marker: PhantomData,
        }))
    }

    fn apply<'data>(
        self,
        data: BytesOrMapping<'data>,
    ) -> Result<Option<BytesOrMapping<'data>>, LoaderError> {
        let mut data = data.into_copy_on_write()?;
        let bytes = data
            .as_mut()
            .expect("copy-on-write buffer should be available");

        let (header, _) = pod::from_bytes_mut::<Elf>(bytes)
            .map_err(|_| LoaderError::format(SectionHeaderRepairError::InvalidFileHeader))?;

        tracing::warn!("ignoring invalid ELF section headers; loading from program headers");
        header.clear_section_headers(self.endian);

        Ok(Some(data))
    }
}
