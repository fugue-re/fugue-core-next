use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Range;

use object::endian::LittleEndian as LE;
use object::pe::{ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, ImageSectionHeader};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
use object::{FileKind, pod};
use thiserror::Error;

use crate::ir::RawAddress;
use crate::loader::LoaderError;
use crate::types::BytesOrMapping;

#[derive(Debug, Error)]
enum SectionTableRepairError {
    #[error("invalid section alignment")]
    InvalidSectionAlignment,
    #[error("invalid section table")]
    InvalidSectionTable,
}

pub(super) fn try_repair<'data>(
    data: BytesOrMapping<'data>,
) -> Result<Option<BytesOrMapping<'data>>, LoaderError> {
    match FileKind::parse(data.as_ref()).map_err(LoaderError::format)? {
        FileKind::Pe32 => {
            let Some(plan) = SectionTableRepairPlan::<ImageNtHeaders32>::try_new(&data)? else {
                return Ok(None);
            };
            plan.apply(data)
        }
        FileKind::Pe64 => {
            let Some(plan) = SectionTableRepairPlan::<ImageNtHeaders64>::try_new(&data)? else {
                return Ok(None);
            };
            plan.apply(data)
        }
        _ => {
            tracing::trace!("section table repair is not applicable");
            Ok(None)
        }
    }
}

struct SectionTableRepairPlan<Pe>
where
    Pe: ImageNtHeaders,
{
    table_range: Range<usize>,
    section_count: usize,
    input_len: u64,
    _marker: PhantomData<Pe>,
}

impl<Pe> SectionTableRepairPlan<Pe>
where
    Pe: ImageNtHeaders,
{
    fn try_new(data: &[u8]) -> Result<Option<Self>, LoaderError> {
        let dos = ImageDosHeader::parse(data).map_err(LoaderError::format)?;
        let mut offset = dos.nt_headers_offset() as u64;
        let (nt, _) = Pe::parse(data, &mut offset).map_err(LoaderError::format)?;
        let sections = nt.sections(data, offset).map_err(LoaderError::format)?;

        let section_alignment = nt.optional_header().section_alignment() as u64;
        if section_alignment == 0 {
            return Err(LoaderError::format(
                SectionTableRepairError::InvalidSectionAlignment,
            ));
        }

        let input_len = u64::try_from(data.len())
            .map_err(|_| LoaderError::format(SectionTableRepairError::InvalidSectionTable))?;
        let table_range = Self::section_table_range(offset, sections.len(), data.len())
            .ok_or_else(|| LoaderError::format(SectionTableRepairError::InvalidSectionTable))?;

        let mut virtual_extent = 0u64;
        let mut raw_extent = 0u64;
        let mut has_repairable_section = false;

        for section in sections.iter() {
            let virtual_size = section.virtual_size.get(LE) as u64;
            let virtual_address = section.virtual_address.get(LE) as u64;
            let size_of_raw_data = section.size_of_raw_data.get(LE) as u64;
            let pointer_to_raw_data = section.pointer_to_raw_data.get(LE) as u64;

            if virtual_size > 0 {
                let section_end = virtual_address.checked_add(virtual_size).ok_or_else(|| {
                    LoaderError::address_overflow(RawAddress::from(virtual_address))
                })?;

                let align_mask = section_alignment.wrapping_sub(1);
                let end = section_end.wrapping_add(align_mask) & !align_mask;
                if end < section_end {
                    return Err(LoaderError::address_overflow(RawAddress::from(
                        virtual_address,
                    )));
                }

                virtual_extent = virtual_extent.max(end);
                has_repairable_section |= section_end <= input_len;
            }

            if size_of_raw_data > 0 {
                let end = pointer_to_raw_data
                    .checked_add(size_of_raw_data)
                    .ok_or_else(|| {
                        LoaderError::address_overflow(RawAddress::from(pointer_to_raw_data))
                    })?;

                raw_extent = raw_extent.max(end);
            }
        }

        if input_len < virtual_extent || virtual_extent <= raw_extent || !has_repairable_section {
            tracing::trace!("section table repair is not applicable");
            return Ok(None);
        }

        Ok(Some(Self {
            table_range,
            section_count: sections.len(),
            input_len,
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

        let table = bytes
            .get_mut(self.table_range)
            .ok_or_else(|| LoaderError::format(SectionTableRepairError::InvalidSectionTable))?;

        let (sections, _) =
            pod::slice_from_bytes_mut::<ImageSectionHeader>(table, self.section_count)
                .map_err(|_| LoaderError::format(SectionTableRepairError::InvalidSectionTable))?;

        let mut repaired = false;

        for section in sections {
            let virtual_size = section.virtual_size.get(LE);
            let virtual_address = section.virtual_address.get(LE);

            if virtual_size == 0 {
                continue;
            }

            let section_end = (virtual_address as u64)
                .checked_add(virtual_size as u64)
                .ok_or_else(|| LoaderError::address_overflow(RawAddress::from(virtual_address)))?;

            if section_end > self.input_len {
                tracing::trace!("virtual range exceeds input length; skipping");
                continue;
            }

            if section.pointer_to_raw_data.get(LE) != virtual_address
                || section.size_of_raw_data.get(LE) != virtual_size
            {
                section.pointer_to_raw_data.set(LE, virtual_address);
                section.size_of_raw_data.set(LE, virtual_size);
                repaired = true;
            }
        }

        Ok(repaired.then_some(data))
    }

    fn section_table_range(
        offset: u64,
        section_count: usize,
        data_len: usize,
    ) -> Option<Range<usize>> {
        let start = usize::try_from(offset).ok()?;
        let len = section_count.checked_mul(size_of::<ImageSectionHeader>())?;
        let end = start.checked_add(len)?;

        (end <= data_len).then_some(start..end)
    }
}
